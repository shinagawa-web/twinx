//! TLS: connections accepted on "listen ... ssl" and connections to proxied
//! servers with "proxy_pass https://". The rest of twinx reads and writes plain
//! HTTP; a thread of each TLS connection passes the decrypted bytes through a
//! Unix socket pair, whose other end twinx uses as it uses a TCP connection.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime};
use x509_parser::prelude::{ASN1Time, CertificateRevocationList, FromDer, GeneralName, X509Certificate, X509Version};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, ClientConnection, Connection, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

use crate::conf::Config;

/// How long a client has to finish its handshake, as client_header_timeout's default.
const HANDSHAKE: Duration = Duration::from_secs(60);

/// A certificate chain and its private key, in PEM. An encrypted key (PKCS #8)
/// is decrypted with the first of the passwords that works, as
/// ssl_password_file has them, one on each line.
fn load(cert: &Path, key: &Path, passwords: Option<&Path>) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    Ok((chain(cert)?, private_key(key, passwords)?.0))
}

/// The certificates of a certificate file, in PEM.
fn chain(cert: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let chain = CertificateDer::pem_file_iter(cert).and_then(|certs| certs.collect::<Result<Vec<_>, _>>()).ok().filter(|c| !c.is_empty());
    chain.ok_or_else(|| format!("cannot load certificate \"{}\"", cert.display()))
}

/// The private key of a key file, in PEM, and whether it was encrypted.
fn private_key(key: &Path, passwords: Option<&Path>) -> Result<(PrivateKeyDer<'static>, bool), String> {
    let text = std::fs::read_to_string(key).unwrap_or_default();
    let passwords = passwords.map(|p| std::fs::read_to_string(p).map_err(|e| format!("open() \"{}\" failed ({e})", p.display()))).transpose()?.unwrap_or_default();
    let encrypted = pkcs8::der::Document::from_pem(&text).ok().filter(|(label, _)| *label == "ENCRYPTED PRIVATE KEY").map(|(_, doc)| doc);
    let decrypt = |doc: &pkcs8::der::Document| passwords.lines().find_map(|p| pkcs8::EncryptedPrivateKeyInfoRef::try_from(doc.as_bytes()).ok()?.decrypt(p).ok());
    let found = match &encrypted { Some(doc) => decrypt(doc).map(|d| PrivateKeyDer::Pkcs8(d.as_bytes().to_vec().into())), None => PrivateKeyDer::from_pem_slice(text.as_bytes()).ok() };
    let found = found.filter(|k| provider().key_provider.load_private_key(k.clone_key()).is_ok());
    Ok((found.ok_or_else(|| format!("cannot load certificate key \"{}\"", key.display()))?, encrypted.is_some()))
}

/// proxy_ssl_certificate_cache: the certificates and keys loaded for
/// connections to proxied servers, by file, as nginx keeps them. At most max
/// of them are kept, the least recently used one going first; one not used
/// for inactive seconds goes when another comes in. After valid seconds, a
/// file whose modification time or inode changed is loaded again. Encrypted
/// keys are never kept.
#[derive(Debug)]
pub struct CertCache {
    max: usize,
    valid: u64,
    inactive: u64,
    /// The least recently used first.
    nodes: Mutex<Vec<Node>>,
}

#[derive(Debug)]
struct Node {
    key: bool,
    path: PathBuf,
    value: Object,
    created: u64,
    accessed: u64,
    file: (i64, u64),
}

/// A certificate chain, or a private key.
#[derive(Debug)]
struct Object {
    chain: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
}

impl Object {
    fn copy(&self) -> Object {
        Object { chain: self.chain.clone(), key: self.key.as_ref().map(PrivateKeyDer::clone_key) }
    }
}

/// A file's modification time and inode.
fn file(path: &Path) -> Option<(i64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.mtime(), m.ino()))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl CertCache {
    pub fn new(max: usize, valid: u64, inactive: u64) -> CertCache {
        CertCache { max, valid, inactive, nodes: Mutex::new(Vec::new()) }
    }

    /// The object of a file, kept or loaded by create (which also says whether
    /// it must not be kept); invalidate loads a kept one again.
    fn fetch(&self, key: bool, path: &Path, invalidate: bool, create: &dyn Fn() -> Result<(Object, bool), String>) -> Result<Object, String> {
        let (now, mut nodes) = (now(), self.nodes.lock().unwrap());
        if let Some(i) = nodes.iter().position(|n| n.key == key && n.path == path) {
            // One that fails to load or must not be kept is no longer kept.
            let mut node = nodes.remove(i);
            let stale = invalidate || now.saturating_sub(node.created) > self.valid;
            let changed = if stale { file(path) } else { Some(node.file) };
            if invalidate || changed != Some(node.file) {
                node.file = changed.unwrap_or_default();
                let (value, uncached) = create()?;
                if uncached { return Ok(value) }
                node.value = value;
            }
            if stale { node.created = now; }
            node.accessed = now;
            let value = node.value.copy();
            nodes.push(node);
            return Ok(value);
        }
        let (value, uncached) = create()?;
        if uncached { return Ok(value) }
        self.expire(&mut nodes, 1, now);
        if nodes.len() >= self.max { self.expire(&mut nodes, 0, now); }
        nodes.push(Node { key, path: path.into(), value: value.copy(), created: now, accessed: now, file: file(path).unwrap_or_default() });
        Ok(value)
    }

    /// Removes up to two objects not used for inactive seconds, the least
    /// recently used one first; with n 0, the least recently used one in any case before them.
    fn expire(&self, nodes: &mut Vec<Node>, mut n: u32, now: u64) {
        while n < 3 && !nodes.is_empty() {
            if n != 0 && now.saturating_sub(nodes[0].accessed) <= self.inactive { return }
            n += 1;
            nodes.remove(0);
        }
    }
}

/// The certificates of a file, in PEM, that clients' certificates are verified with.
fn trusted(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path).and_then(|certs| certs.collect::<Result<Vec<_>, _>>());
    certs.map_err(|_| format!("SSL_CTX_load_verify_locations(\"{}\") failed", path.display()))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What a server takes TLS connections with: its certificate, and when
/// ssl_verify_client is not off, the certificates clients' certificates are
/// verified with (ssl_trusted_certificate, ssl_client_certificate).
#[derive(Debug)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    trusted: Vec<CertificateDer<'static>>,
}

/// How a server resumes clients' sessions: with tickets (ssl_session_tickets),
/// from sessions it keeps (ssl_session_cache not off or none), and for how
/// many seconds after they began (ssl_session_timeout).
#[derive(Debug, Clone, Copy)]
pub struct Sessions {
    pub tickets: bool,
    pub cache: bool,
    pub timeout: u64,
}

impl Default for Sessions {
    fn default() -> Sessions {
        Sessions { tickets: true, cache: false, timeout: 300 }
    }
}

/// Tickets that resume a session only until ssl_session_timeout passed since
/// it began: each is stamped with the time it was made. Sessions kept in the
/// cache, which TLS 1.3 clients do not use while tickets are on, do not expire yet.
#[derive(Debug)]
struct Timed<T>(T, u64);

impl<T> Timed<T> {
    fn stamp(data: &[u8]) -> Vec<u8> {
        now().to_be_bytes().iter().chain(data).copied().collect()
    }

    fn fresh(&self, data: Vec<u8>) -> Option<Vec<u8>> {
        let (made, rest) = data.split_at_checked(8)?;
        (now() <= u64::from_be_bytes(made.try_into().ok()?) + self.1).then(|| rest.to_vec())
    }
}

impl rustls::server::ProducesTickets for Timed<Arc<dyn rustls::server::ProducesTickets>> {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.1.min(u32::MAX.into()) as u32
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(&Self::stamp(plain))
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.fresh(self.0.decrypt(cipher)?)
    }
}

/// The files of ssl_certificate, ssl_certificate_key and ssl_password_file;
/// whether clients are asked for a certificate (ssl_verify_client not off),
/// the files of the certificates theirs are verified with, and how their
/// sessions are resumed.
pub fn server(cert: &Path, key: &Path, passwords: Option<&Path>, verify: bool, trust: &[&Path], sessions: Sessions) -> Result<ServerTls, String> {
    let (chain, key) = load(cert, key, passwords)?;
    let trusted = trust.iter().map(|p| trusted(p)).collect::<Result<Vec<_>, _>>()?.concat();
    let builder = ServerConfig::builder();
    let builder = if verify { builder.with_client_cert_verifier(Arc::new(AnyClient(provider().signature_verification_algorithms))) } else { builder.with_no_client_auth() };
    let mut config = builder.with_single_cert(chain, key).map_err(|e| format!("cannot load certificate \"{}\" ({e})", cert.display()))?;
    config.session_storage = if sessions.cache { rustls::server::ServerSessionMemoryCache::new(20480) } else { Arc::new(rustls::server::NoServerSessionStorage {}) };
    if sessions.tickets { config.ticketer = Arc::new(Timed(rustls::crypto::ring::Ticketer::new().map_err(|e| e.to_string())?, sessions.timeout)); }
    Ok(ServerTls { config: Arc::new(config), trusted })
}

/// What the variables tell of a TLS connection: the protocol ($ssl_protocol,
/// "TLSv1.3"), whether its session was reused ($ssl_session_reused), how the
/// client's certificate was verified ($ssl_client_verify: NONE, SUCCESS or
/// FAILED:reason), its subject ($ssl_client_s_dn) and the name the client
/// asked for with SNI ($ssl_server_name, empty without one); the session's
/// identifier ($ssl_session_id), the cipher suite ($ssl_cipher) and those the
/// client offered ($ssl_ciphers), and the client's certificate.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Session {
    pub protocol: String,
    pub server_name: String,
    pub reused: bool,
    pub verify: String,
    pub subject: Option<String>,
    pub id: String,
    pub cipher: String,
    pub ciphers: String,
    pub cert: Option<CertificateDer<'static>>,
}

/// OpenSSL's names of cipher suites, as $ssl_cipher and $ssl_ciphers give them.
const CIPHERS: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"), (0x1302, "TLS_AES_256_GCM_SHA384"), (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"), (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    (0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"), (0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"), (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"),
    (0xc030, "ECDHE-RSA-AES256-GCM-SHA384"), (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305"), (0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    (0xccaa, "DHE-RSA-CHACHA20-POLY1305"), (0x009e, "DHE-RSA-AES128-GCM-SHA256"), (0x009f, "DHE-RSA-AES256-GCM-SHA384"),
    (0xc023, "ECDHE-ECDSA-AES128-SHA256"), (0xc024, "ECDHE-ECDSA-AES256-SHA384"), (0xc027, "ECDHE-RSA-AES128-SHA256"),
    (0xc028, "ECDHE-RSA-AES256-SHA384"), (0x0067, "DHE-RSA-AES128-SHA256"), (0x006b, "DHE-RSA-AES256-SHA256"),
    (0xc009, "ECDHE-ECDSA-AES128-SHA"), (0xc00a, "ECDHE-ECDSA-AES256-SHA"), (0xc013, "ECDHE-RSA-AES128-SHA"),
    (0xc014, "ECDHE-RSA-AES256-SHA"), (0x0033, "DHE-RSA-AES128-SHA"), (0x0039, "DHE-RSA-AES256-SHA"),
    (0x009c, "AES128-GCM-SHA256"), (0x009d, "AES256-GCM-SHA384"), (0x003c, "AES128-SHA256"), (0x003d, "AES256-SHA256"),
    (0x002f, "AES128-SHA"), (0x0035, "AES256-SHA"), (0xc0ad, "ECDHE-ECDSA-AES256-CCM"), (0xc0ac, "ECDHE-ECDSA-AES128-CCM"),
    (0xc09f, "DHE-RSA-AES256-CCM"), (0xc09e, "DHE-RSA-AES128-CCM"), (0xc09d, "AES256-CCM"), (0xc09c, "AES128-CCM"),
    (0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"), (0x5600, "TLS_FALLBACK_SCSV"),
];

/// The name OpenSSL gives a cipher suite; one it does not know is "0x" and its number.
fn cipher(id: u16) -> String {
    CIPHERS.iter().find(|c| c.0 == id).map_or_else(|| format!("0x{id:04x}"), |c| c.1.to_string())
}

/// A name as OpenSSL writes it: RFC 2253, the last attribute first
/// ("CN=name,O=organization"), or legacy, the first first ("/O=organization/CN=name").
fn name(name: &x509_parser::x509::X509Name, legacy: bool) -> String {
    let registry = x509_parser::objects::oid_registry();
    let attr = |a: &x509_parser::x509::AttributeTypeAndValue| format!("{}={}", x509_parser::objects::oid2abbrev(a.attr_type(), registry).map_or_else(|_| a.attr_type().to_id_string(), str::to_string), a.as_str().unwrap_or_default());
    let rdns = name.iter_rdn().map(|rdn| rdn.iter().map(attr).collect::<Vec<_>>());
    if legacy { return rdns.flatten().map(|a| format!("/{a}")).collect() }
    rdns.map(|a| a.join("+")).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(",")
}

impl Session {
    /// The variables of the client's certificate: $ssl_client_i_dn (its issuer),
    /// $ssl_client_s_dn_legacy and $ssl_client_i_dn_legacy, $ssl_client_v_start
    /// and $ssl_client_v_end (when it is valid, as "Nov 22 10:00:00 2026 GMT"),
    /// and $ssl_client_v_remain (the days left); empty without a certificate.
    pub fn client_var(&self, var: &str) -> String {
        let Some((_, cert)) = self.cert.as_ref().and_then(|c| x509_parser::parse_x509_certificate(c).ok()) else { return String::new() };
        let time = |t: ASN1Time| chrono::DateTime::from_timestamp(t.timestamp(), 0).map(|t| t.format("%b %e %H:%M:%S %Y GMT").to_string()).unwrap_or_default();
        match var {
            "i_dn" => name(cert.issuer(), false),
            "s_dn_legacy" => name(cert.subject(), true),
            "i_dn_legacy" => name(cert.issuer(), true),
            "v_start" => time(cert.validity().not_before),
            "v_end" => time(cert.validity().not_after),
            _ => ((cert.validity().not_after.timestamp() - now() as i64) / 86400).max(0).to_string(),
        }
    }
}

/// Takes a TLS connection from a client on a listening address: the server
/// its SNI name selects (as the Host header selects one) does the handshake;
/// then the plain end of the connection.
pub fn accept(mut tcp: TcpStream, config: &Config, listen: SocketAddr) -> Option<(TcpStream, Session)> {
    let _ = tcp.set_read_timeout(Some(HANDSHAKE));
    let mut acceptor = rustls::server::Acceptor::default();
    let hello = loop {
        if acceptor.read_tls(&mut tcp).ok().filter(|n| *n > 0).is_none() { return None }
        if let Some(hello) = acceptor.accept().ok()? { break hello }
    };
    let name = hello.client_hello().server_name().unwrap_or_default().to_string();
    let tls = crate::http::server(config, listen, hello.client_hello().server_name()).0.tls.as_ref()?;
    let ciphers = hello.client_hello().cipher_suites().iter().map(|c| cipher(u16::from(*c))).collect::<Vec<_>>().join(":");
    let mut conn = hello.into_connection(tls.config.clone()).ok()?;
    // A session keeps its identifier when it is resumed, as OpenSSL's does.
    let id = conn.received_resumption_data().map_or_else(|| { let mut id = [0u8; 32]; provider().secure_random.fill(&mut id).map(|_| id.to_vec()) }, |id| Ok(id.to_vec())).ok()?;
    conn.set_resumption_data(&id);
    let (stream, mut session, chain) = pipe(tcp, conn.into(), HANDSHAKE).ok()?;
    (session.server_name, session.verify, session.subject) = (name, verified(&chain, &tls.trusted), chain.first().and_then(|c| subject(c)));
    (session.id, session.ciphers, session.cert) = (id.iter().map(|b| format!("{b:02x}")).collect(), ciphers, chain.first().cloned());
    Some((stream, session))
}

/// Clients may send a certificate, which the handshake takes whatever it is;
/// whether it verifies is told by $ssl_client_verify.
#[derive(Debug)]
struct AnyClient(WebPkiSupportedAlgorithms);

impl ClientCertVerifier for AnyClient {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    // Only a client that does not take TLS 1.3 has this called.
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls12_signature(m, c, d, &self.0) }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// How a client's certificate chain verifies against the trusted
/// certificates, as $ssl_client_verify tells it. A trusted certificate is
/// taken as it is, as OpenSSL takes a self-signed one in its store.
fn verified(chain: &[CertificateDer<'static>], trusted: &[CertificateDer<'static>]) -> String {
    let Some(leaf) = chain.first() else { return "NONE".to_string() };
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(trusted.iter().cloned());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build();
    let ok = trusted.contains(leaf) || verifier.is_ok_and(|v| v.verify_client_cert(leaf, &chain[1..], UnixTime::now()).is_ok());
    let self_signed = x509_parser::parse_x509_certificate(leaf).is_ok_and(|(_, c)| c.subject().as_raw() == c.issuer().as_raw());
    if ok { "SUCCESS".to_string() } else { format!("FAILED:{}", if self_signed { "self-signed certificate" } else { "unable to get local issuer certificate" }) }
}

/// The subject of a certificate as RFC 2253 writes it, as $ssl_client_s_dn
/// gives it: the last attribute first, "CN=name,O=organization".
fn subject(der: &[u8]) -> Option<String> {
    Some(name(x509_parser::parse_x509_certificate(der).ok()?.1.subject(), false))
}

/// A proxied server's certificate is verified with proxy_ssl_verify on, and
/// not with it off; the handshake's signatures are.
#[derive(Debug)]
struct Proxied(WebPkiSupportedAlgorithms, Option<Verify>);

impl ServerCertVerifier for Proxied {
    fn verify_server_cert(&self, end: &CertificateDer, sent: &[CertificateDer], name: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        self.1.as_ref().map_or(Ok(()), |v| v.check(end, sent, name))?;
        Ok(ServerCertVerified::assertion())
    }

    // Only a proxied server that does not take TLS 1.3 has this called.
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls12_signature(m, c, d, &self.0) }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// proxy_ssl_verify: what proxied servers' certificates are verified with,
/// as OpenSSL verifies them for nginx: the certificates of
/// proxy_ssl_trusted_certificate, the CRLs of proxy_ssl_crl, if any, and
/// proxy_ssl_verify_depth; the name is the one the connection is made to.
#[derive(Debug)]
pub struct Verify {
    trusted: Vec<CertificateDer<'static>>,
    crls: Option<Vec<Vec<u8>>>,
    depth: usize,
}

/// The files of proxy_ssl_trusted_certificate (none trusts nothing) and proxy_ssl_crl, and proxy_ssl_verify_depth.
pub fn verify(trust: Option<&Path>, crl: Option<&Path>, depth: usize) -> Result<Verify, String> {
    let crls = crl.map(|p| CertificateRevocationListDer::pem_file_iter(p).and_then(|c| c.map(|c| c.map(|c| c.to_vec())).collect()).map_err(|_| format!("X509_LOOKUP_load_file(\"{}\") failed", p.display()))).transpose()?;
    Ok(Verify { trusted: trust.map(trusted).transpose()?.unwrap_or_default(), crls, depth })
}

impl Verify {
    fn check(&self, end: &CertificateDer, sent: &[CertificateDer], name: &ServerName) -> Result<(), rustls::Error> {
        let name = match name { ServerName::IpAddress(ip) => IpAddr::from(*ip).to_string(), n => n.to_str().into_owned() };
        let leaf = verify_chain(end, sent, &self.trusted, self.crls.as_deref(), self.depth).map_err(|e| rustls::Error::General(format!("upstream SSL certificate verify error: ({e})")))?;
        for_name(&leaf, &name).then_some(()).ok_or_else(|| rustls::Error::General(format!("upstream SSL certificate does not match \"{name}\"")))
    }
}

/// Verifies a certificate chain as OpenSSL does without partial chains: from
/// the peer's certificate up through the issuers it sent or the trusted ones,
/// each signing the one below, to a trusted self-signed certificate, the
/// chain at most depth + 1 certificates long with it; all of them valid now, the issuers CAs, and
/// with CRLs, none revoked by a CRL of its issuer, which each must have (as
/// X509_V_FLAG_CRL_CHECK_ALL). Gives the peer's certificate parsed, or the
/// error as OpenSSL words it.
fn verify_chain<'a>(end: &'a [u8], sent: &'a [CertificateDer], trusted: &'a [CertificateDer], crls: Option<&'a [Vec<u8>]>, depth: usize) -> Result<X509Certificate<'a>, &'static str> {
    let parse = |d: &'a [u8]| X509Certificate::from_der(d).ok().map(|(_, c)| c);
    let (anchors, sent): (Vec<_>, Vec<_>) = (trusted.iter().filter_map(|d| parse(d)).collect(), sent.iter().filter_map(|d| parse(d)).collect());
    let mut chain = vec![parse(end).ok_or("unable to decode certificate")?];
    loop {
        let cur = chain.last().unwrap();
        let self_signed = cur.subject().as_raw() == cur.issuer().as_raw();
        if self_signed && trusted.iter().any(|t| t.as_ref() == cur.as_raw()) { break }
        if self_signed { return Err(if chain.len() == 1 { "self-signed certificate" } else { "self-signed certificate in certificate chain" }) }
        let issued = |c: &&X509Certificate<'a>| c.subject().as_raw() == cur.issuer().as_raw() && cur.verify_signature(Some(c.public_key())).is_ok();
        let issuer = anchors.iter().find(issued).or_else(|| sent.iter().find(issued)).ok_or("unable to get local issuer certificate")?.clone();
        if chain.len() > depth { return Err("certificate chain too long") }
        chain.push(issuer);
    }
    if let Some(c) = chain.iter().find(|c| !c.validity().is_valid()) { return Err(if c.validity().not_before > ASN1Time::now() { "certificate is not yet valid" } else { "certificate has expired" }) }
    if chain[1..].iter().any(|c| !c.is_ca() && c.version() != X509Version::V1) { return Err("invalid CA certificate") }
    let Some(crls) = crls else { return Ok(chain.swap_remove(0)) };
    let crls: Vec<_> = crls.iter().filter_map(|d| CertificateRevocationList::from_der(d).ok().map(|(_, c)| c)).collect();
    for (i, c) in chain.iter().enumerate() {
        let issuer = chain.get(i + 1).unwrap_or(c);
        let crl = crls.iter().find(|l| l.issuer().as_raw() == c.issuer().as_raw() && l.verify_signature(issuer.public_key()).is_ok()).ok_or("unable to get certificate CRL")?;
        if crl.next_update().is_some_and(|t| t < ASN1Time::now()) { return Err("CRL has expired") }
        if crl.iter_revoked_certificates().any(|r| r.raw_serial() == c.raw_serial()) { return Err("certificate revoked") }
    }
    Ok(chain.swap_remove(0))
}

/// Whether a certificate is for a name, as X509_check_host checks it:
/// against the DNS names of subjectAltName, or without them, the subject's
/// last common name (see host_matches).
fn for_name(cert: &X509Certificate, name: &str) -> bool {
    let names = cert.subject_alternative_name().ok().flatten().map(|e| e.value.general_names.clone()).unwrap_or_default();
    let mut dns: Vec<&str> = names.iter().filter_map(|g| if let GeneralName::DNSName(d) = g { Some(*d) } else { None }).collect();
    if dns.is_empty() { dns.extend(cert.subject().iter_common_name().last().and_then(|a| a.as_str().ok())); }
    dns.iter().any(|p| host_matches(p, name))
}

/// Whether a name matches a name of a certificate, ignoring case. A "*" in
/// its leftmost label, when two labels or more follow, stands for any
/// characters within one label (at least one when it is the whole label).
fn host_matches(pattern: &str, name: &str) -> bool {
    let (Some((p, rest)), Some((n, nrest))) = (pattern.split_once('.'), name.split_once('.')) else { return pattern.eq_ignore_ascii_case(name) };
    let Some((pre, post)) = p.split_once('*').filter(|(_, post)| rest.contains('.') && !post.contains('*')) else { return pattern.eq_ignore_ascii_case(name) };
    let n = n.as_bytes();
    rest.eq_ignore_ascii_case(nrest) && n.len() >= (pre.len() + post.len()).max(1) && n[..pre.len()].eq_ignore_ascii_case(pre.as_bytes()) && n[n.len() - post.len()..].eq_ignore_ascii_case(post.as_bytes())
}

/// What connections to proxied servers are made with: with SNI when
/// proxy_ssl_server_name is on (sni), for the name connect gives; reusing the sessions of earlier
/// connections when proxy_ssl_session_reuse is on; with the certificate of
/// proxy_ssl_certificate, proxy_ssl_certificate_key and proxy_ssl_password_file, if any;
/// verifying their certificates with verify, if any (proxy_ssl_verify on).
pub fn client((reuse, sni): (bool, bool), cert: Option<(&Path, &Path, Option<&Path>)>, verify: Option<Verify>) -> Result<Arc<ClientConfig>, String> {
    let mut c = match cert.map(|(c, k, p)| load(c, k, p)).transpose()? {
        Some((chain, key)) => proxied(verify).with_client_auth_cert(chain, key).map_err(|e| e.to_string())?,
        None => proxied(verify).with_no_client_auth(),
    };
    c.enable_sni = sni;
    if !reuse { c.resumption = rustls::client::Resumption::disabled(); }
    Ok(Arc::new(c))
}

fn proxied(verify: Option<Verify>) -> rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert> {
    let verifier = Arc::new(Proxied(provider().signature_verification_algorithms, verify));
    ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier)
}

/// What one connection to a proxied server is made with when variables name
/// the files of proxy_ssl_certificate and proxy_ssl_certificate_key: base's
/// settings, with the certificate and key of those files, taken from the
/// cache when there is one. A key that does not match its certificate, as a
/// cache updated between the two may give, has both loaded again.
pub fn client_cert(base: &Arc<ClientConfig>, (cert, key, passwords): (&Path, &Path, Option<&Path>), cache: Option<&CertCache>) -> Result<Arc<ClientConfig>, String> {
    let fetch = |key: bool, path: &Path, invalidate: bool, create: &dyn Fn() -> Result<(Object, bool), String>| match cache { Some(c) => c.fetch(key, path, invalidate, create), None => create().map(|o| o.0) };
    let mut invalidate = false;
    loop {
        let chain = fetch(false, cert, invalidate, &|| Ok((Object { chain: chain(cert)?, key: None }, false)))?.chain;
        let pkey = fetch(true, key, invalidate, &|| private_key(key, passwords).map(|(k, encrypted)| (Object { chain: Vec::new(), key: Some(k) }, encrypted)))?.key;
        let config = proxied(None).with_client_auth_cert(chain, pkey.ok_or("no key")?);
        if !invalidate && matches!(config, Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch))) { invalidate = true; continue }
        let mut c = (**base).clone();
        c.client_auth_cert_resolver = config.map_err(|e| format!("SSL_use_PrivateKey(\"{}\") failed ({e})", key.display()))?.client_auth_cert_resolver;
        return Ok(Arc::new(c));
    }
}

/// Connects to a proxied server over TLS, to the name its certificate is
/// verified for and SNI sends, if any (one that is no name fails; an address is not sent); the plain end of the
/// connection, or the error the handshake failed with (WouldBlock once the timeout passed).
pub fn connect(tcp: TcpStream, (peer, name): (IpAddr, Option<&str>), timeout: Duration, config: &Arc<ClientConfig>) -> std::io::Result<TcpStream> {
    let name = name.map_or(Ok(ServerName::from(peer)), |n| ServerName::try_from(n.to_string()).map_err(std::io::Error::other))?;
    let conn = ClientConnection::new(config.clone(), name).map_err(std::io::Error::other)?;
    pipe(tcp, conn.into(), timeout).map(|(s, ..)| s)
}

/// Completes the handshake, then passes data between the TLS connection and
/// one end of a socket pair in a thread of its own, and gives the other end,
/// on which twinx reads and writes as on a TCP connection.
/// Also gives the certificates the peer sent.
fn pipe(mut tcp: TcpStream, mut tls: Connection, timeout: Duration) -> std::io::Result<(TcpStream, Session, Vec<CertificateDer<'static>>)> {
    let _ = tcp.set_read_timeout(Some(timeout));
    while tls.is_handshaking() { tls.complete_io(&mut tcp)?; }
    let _ = tcp.set_read_timeout(None);
    let protocol = tls.protocol_version().map(|v| format!("{v:?}").replace('_', ".")).unwrap_or_default();
    let cipher = tls.negotiated_cipher_suite().map(|c| cipher(u16::from(c.suite()))).unwrap_or_default();
    let session = Session { protocol, reused: tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed), cipher, ..Session::default() };
    let chain = tls.peer_certificates().map(<[_]>::to_vec).unwrap_or_default();
    let (ours, theirs) = UnixStream::pair()?;
    std::thread::spawn(move || pump(tcp, tls, theirs));
    // SAFETY: the descriptor is a connected stream socket that nothing else owns; the
    // calls twinx makes on a TcpStream (read, write, shutdown, timeouts, poll) work on it.
    Ok((unsafe { TcpStream::from_raw_fd(ours.into_raw_fd()) }, session, chain))
}

/// Decrypts what the peer sends into the socket pair, and encrypts what twinx
/// writes there, until both have closed their sides. Once twinx has closed
/// its side, the peer gets a close_notify and the end of the stream, and up to
/// five seconds to close its own, as a lingering close waits.
fn pump(mut tcp: TcpStream, mut tls: Connection, mut plain: UnixStream) {
    let poll = |fd: i32| libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let (mut fds, mut buf) = ([poll(tcp.as_raw_fd()), poll(plain.as_raw_fd())], [0u8; 16384]);
    loop {
        while let Ok(n @ 1..) = tls.reader().read(&mut buf) { if plain.write_all(&buf[..n]).is_err() { return } }
        while tls.wants_write() { if tls.write_tls(&mut tcp).is_err() { return } }
        if fds[1].fd < 0 { let _ = tcp.shutdown(Shutdown::Write); }
        let wait = if fds[1].fd < 0 { 5000 } else { -1 };
        // SAFETY: fds is an array of two pollfd that lives through the call.
        if fds[0].fd < 0 && fds[1].fd < 0 || unsafe { libc::poll(fds.as_mut_ptr(), 2, wait) } <= 0 { return }
        // The peer closed its side, or sent what is not TLS (the alert goes back first).
        if fds[0].revents != 0 && (!matches!(tls.read_tls(&mut tcp), Ok(1..)) || tls.process_new_packets().is_err()) {
            let _ = plain.shutdown(Shutdown::Write);
            fds[0].fd = -1;
        }
        if fds[1].revents != 0 {
            match plain.read(&mut buf) {
                Ok(n @ 1..) => { let _ = tls.writer().write_all(&buf[..n]); }
                _ => { tls.send_close_notify(); fds[1].fd = -1; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A self-signed P-256 certificate for localhost and its key, made by openssl only for these tests.
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBfzCCASWgAwIBAgIUL/k6KpzbDaaBQg3M39x5hxZbbP0wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTEyMjA3MTIwNloYDzIxMjYxMDI5
MDcxMjA2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQV8MnIDQbB8/uMHXJwABFJKcRsUCxXPNBj+/rwm0WoMqtlMzej/znJ
b0K03rUCX+VpEXgEh09RKGvdwPekFRxUo1MwUTAdBgNVHQ4EFgQU309aNfa5jPXn
4RFv+yUFxPorPDEwHwYDVR0jBBgwFoAU309aNfa5jPXn4RFv+yUFxPorPDEwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAk0fv7zTkdaWCsAMhYPTH
46MJDkmwZkVvsVL0qG7rF94CIEQVXimlAO6CUG2+vllY1IOXyT3Aj6CpZw8vYMkx
wYWN
-----END CERTIFICATE-----
";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyVQ8zOCCB5Ypxmn4
9mx0WR6gW23XHmPnXG6EJkf8P8OhRANCAAQV8MnIDQbB8/uMHXJwABFJKcRsUCxX
PNBj+/rwm0WoMqtlMzej/znJb0K03rUCX+VpEXgEh09RKGvdwPekFRxU
-----END PRIVATE KEY-----
";

    /// A root CA, an intermediate CA it signed and an end certificate the
    /// intermediate signed (P-256), with CRLs: the root's revoking nothing,
    /// the intermediate's revoking nothing, and the root's revoking the
    /// intermediate. Made by openssl only for these tests.
    const ROOT: &str = "-----BEGIN CERTIFICATE-----
MIIBYzCCAQqgAwIBAgIUIv/pRqL1Az/j5BHh2Let4xBS2jIwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEcm9vdDAgFw0yNjExMjIwOTQ1MzRaGA8yMTI2MTAyOTA5NDUz
NFowDzENMAsGA1UEAwwEcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABABw
ae10AMAhl8c/BoFz9q/w11p0gkpzzAC2SxnWawPlYQvYh8g8Jqp1YyoK3T1nsF33
w5qmnItsLHRcopZK/tqjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgGGMB0GA1UdDgQWBBRwrEbKw5rBr1CWseCMgK/RhJML+zAKBggqhkjOPQQDAgNH
ADBEAiB4a+vdhEcjCrUyuWZldZUksLYMtq84fO7m1jLtsenSTAIgK3tuL3cBUkgI
IFy7nh4LNruGJY4pdxA84ruSOSlgfxo=
-----END CERTIFICATE-----
";
    const INT: &str = "-----BEGIN CERTIFICATE-----
MIIBczCCARigAwIBAgICEAAwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEcm9vdDAg
Fw0yNjExMjIwOTQ1MzRaGA8yMTI2MTAyOTA5NDUzNFowDjEMMAoGA1UEAwwDaW50
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktCMzU0NVv0Z+DPJbjFgT21DMhog
TOcDyN3aoht5E4dcYU+mCjWBUDHpQdDi9k4rLRcj2hISi95yJQtfBE3WmaNjMGEw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFK5URGEK
vn5ctHP2iDwCqvWS0SkyMB8GA1UdIwQYMBaAFHCsRsrDmsGvUJax4IyAr9GEkwv7
MAoGCCqGSM49BAMCA0kAMEYCIQClDdR8mOhN9TtUT8TggrEiR09w1sPFpaw8uZe/
gIXy7wIhAKfgRdXTI5WZ+1xG+YONzrbNF2/wYkhn6ktkoUAwrLJy
-----END CERTIFICATE-----
";
    const END: &str = "-----BEGIN CERTIFICATE-----
MIIBcDCCARegAwIBAgICEAEwCgYIKoZIzj0EAwIwDjEMMAoGA1UEAwwDaW50MCAX
DTI2MTEyMjA5NDUzNFoYDzIxMjYxMDI5MDk0NTM0WjAOMQwwCgYDVQQDDANlbmQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT6xm5HERgVoebZ6H67ZCF74GeFajaw
FKXmF6lKHOjmIH03bQk5MZJjdckE0FgQjTC9D+zP2W0evumcK2dJR3CTo2MwYTAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU1RTqTPRC
3Tpb95yIPVn7wi4v6RYwHwYDVR0jBBgwFoAUrlREYQq+fly0c/aIPAKq9ZLRKTIw
CgYIKoZIzj0EAwIDRwAwRAIgRpBwhXEdp9/JA49lztWjfdzy9M/KrTA3D8AXD1i8
UW4CICCNDgcxcN0yXyhmyTeQfYsG7BCDWBfCyCP84gEfEO3B
-----END CERTIFICATE-----
";
    const ROOT_CRL: &str = "-----BEGIN X509 CRL-----
MIGWMD0wCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEcm9vdBcNMjYxMTIyMDk0NTM0
WhgPMjEyNjEwMjkwOTQ1MzRaMAoGCCqGSM49BAMCA0kAMEYCIQCS/4IYGgU9omGJ
4UWg11Ujpz2TmQ9sy5rLq0DXtKjvOQIhAPmIZQVF+BFA4vdtCCCb4yxT3mv/6lIK
KvMb7DTelAtI
-----END X509 CRL-----
";
    const INT_CRL: &str = "-----BEGIN X509 CRL-----
MIGVMDwwCgYIKoZIzj0EAwIwDjEMMAoGA1UEAwwDaW50Fw0yNjExMjIwOTQ1MzRa
GA8yMTI2MTAyOTA5NDUzNFowCgYIKoZIzj0EAwIDSQAwRgIhAMipASw24YTfro53
dWN+wM2EflB90tqJyjbgsYP1ykKbAiEA+3eISlmqDMihzNFquUe6FCOZH7+1VP97
gj8U+vs04KU=
-----END X509 CRL-----
";
    const REVOKED_CRL: &str = "-----BEGIN X509 CRL-----
MIGtMFQwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEcm9vdBcNMjYxMTIyMDk0NTM0
WhgPMjEyNjEwMjkwOTQ1MzRaMBUwEwICEAAXDTI2MTEyMjA5NDUzNFowCgYIKoZI
zj0EAwIDSQAwRgIhAKrH2gSMjnYnNwAuqh5X34wyu2L1YI9k8XkzT+cGx1t6AiEA
0R29jMSPXK8ryrqczZDuYUeDGnru7yYK+cOrmnEcL1U=
-----END X509 CRL-----
";

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn crl(pem: &str) -> Vec<u8> {
        CertificateRevocationListDer::from_pem_slice(pem.as_bytes()).unwrap().to_vec()
    }

    #[test]
    fn verifies_chains_as_openssl() {
        let (root, int, end) = (der(ROOT), der(INT), der(END));
        let ok = |sent: &[CertificateDer<'static>], trusted: &[CertificateDer<'static>], crls: Option<&[Vec<u8>]>, depth| verify_chain(&end, sent, trusted, crls, depth).map(|_| ());
        assert_eq!(ok(&[int.clone()], &[root.clone()], None, 2), Ok(()));
        assert_eq!(ok(&[int.clone()], &[root.clone()], None, 1), Err("certificate chain too long"));
        assert_eq!(ok(&[], &[root.clone()], None, 2), Err("unable to get local issuer certificate"));
        // A trusted intermediate is no end: the chain goes on to the root.
        assert_eq!(ok(&[], &[int.clone(), root.clone()], None, 1), Err("certificate chain too long"));
        assert_eq!(ok(&[], &[int.clone()], None, 2), Err("unable to get local issuer certificate"));
        // Every certificate needs a CRL of its issuer, the root its own.
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(ROOT_CRL)]), 2), Err("unable to get certificate CRL"));
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(ROOT_CRL), crl(INT_CRL)]), 2), Ok(()));
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(REVOKED_CRL), crl(INT_CRL)]), 2), Err("certificate revoked"));
        // A self-signed certificate verifies only when it is trusted.
        assert!(verify_chain(&root, &[], &[root.clone()], None, 0).is_ok());
        assert_eq!(verify_chain(&root, &[], &[], None, 0).map(|_| ()), Err("self-signed certificate"));
        assert_eq!(verify_chain(&int, &[root.clone()], &[], None, 1).map(|_| ()), Err("self-signed certificate in certificate chain"));
    }

    #[test]
    fn matches_wildcard_names() {
        assert!(host_matches("example.com", "EXAMPLE.com"));
        assert!(host_matches("*.example.com", "foo.example.com"));
        assert!(!host_matches("*.example.com", "no.match.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.com", "example.com"));
        assert!(host_matches("f*o.example.com", "fo.example.com"));
        assert!(host_matches("f*o.example.com", "FOOO.example.com"));
        assert!(!host_matches("f*o.example.com", "bar.example.com"));
        assert!(!host_matches("**.example.com", "foo.example.com"));
        assert!(!host_matches("*.example.com", "localhost"));
    }

    #[test]
    fn verifies_names_and_loads_files() {
        let dir = dir();
        std::fs::write(dir.join("root.crt"), ROOT).unwrap();
        std::fs::write(dir.join("chain.crl"), format!("{ROOT_CRL}{INT_CRL}")).unwrap();
        let v = verify(Some(&dir.join("root.crt")), Some(&dir.join("chain.crl")), 2).unwrap();
        let name = |n: &str| ServerName::try_from(n.to_string()).unwrap();
        assert!(v.check(&der(END), &[der(INT)], &name("END")).is_ok());
        assert_eq!(v.check(&der(END), &[der(INT)], &name("int")).unwrap_err().to_string(), "unexpected error: upstream SSL certificate does not match \"int\"");
        assert!(v.check(&der(END), &[der(INT)], &name("127.0.0.1")).is_err());
        assert!(verify(None, Some(&dir.join("none")), 1).unwrap_err().starts_with("X509_LOOKUP_load_file("));
        assert!(verify(None, None, 1).unwrap().check(&der(END), &[der(INT)], &name("end")).is_err());
    }

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("twinx-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("c.pem"), CERT).unwrap();
        std::fs::write(dir.join("k.pem"), KEY).unwrap();
        dir
    }

    #[test]
    fn loads_certificates() {
        let dir = dir();
        assert_eq!(load(&dir.join("c.pem"), &dir.join("k.pem"), None).unwrap().0.len(), 1);
        assert_eq!(load(&dir.join("none"), &dir.join("k.pem"), None).unwrap_err(), format!("cannot load certificate \"{}\"", dir.join("none").display()));
        assert_eq!(load(&dir.join("c.pem"), &dir.join("c.pem"), None).unwrap_err(), format!("cannot load certificate key \"{}\"", dir.join("c.pem").display()));
        assert!(load(&dir.join("c.pem"), &dir.join("k.pem"), Some(&dir.join("none"))).unwrap_err().starts_with("open() "));
        assert_eq!(trusted(&dir.join("c.pem")).unwrap().len(), 1);
    }

    #[test]
    fn decrypts_keys_with_the_password_that_works() {
        let dir = dir();
        // The key above, encrypted as openssl does (PBES2, AES-128-CBC) with the password "right".
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjFTCshcGXqRQICCAAw\nDAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEE4Q9tYczPUHfCtbunvgXjcEgZCF\nZEkeGhOhIcDghmEGcasLrWUT9mM7JCtGch9N9XhIdxCtpRVi7y7BdDoJx3qbbuL/\ns13ZM5I8hD8DXSitMu7hbJGEg332YbZ/h8qknf0owJaNNWwj2t2tiOT4gR6Ei9C4\n6HZM+qGHgPRfZoSlQpEBrlAJmGaXPXcBu3LZ1K5KmJbzaz9kp+jdx9GbkrYbH8g=\n-----END ENCRYPTED PRIVATE KEY-----\n";
        std::fs::write(dir.join("e.pem"), encrypted).unwrap();
        std::fs::write(dir.join("passwords"), "wrong\nright\n").unwrap();
        std::fs::write(dir.join("wrong"), "wrong").unwrap();
        assert!(load(&dir.join("c.pem"), &dir.join("e.pem"), Some(&dir.join("passwords"))).is_ok());
        assert!(load(&dir.join("c.pem"), &dir.join("e.pem"), Some(&dir.join("wrong"))).is_err());
    }

    #[test]
    fn verifies_and_names_client_certificates() {
        let cert = CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap();
        assert_eq!(verified(&[], &[]), "NONE");
        assert_eq!(verified(std::slice::from_ref(&cert), std::slice::from_ref(&cert)), "SUCCESS");
        assert_eq!(verified(std::slice::from_ref(&cert), &[]), "FAILED:self-signed certificate");
        assert_eq!(subject(&cert).as_deref(), Some("CN=localhost"));
    }

    #[test]
    fn names_ciphers_and_certificates_as_openssl() {
        assert_eq!((cipher(0x1302), cipher(0xc030), cipher(0x00ff), cipher(0xabcd)), ("TLS_AES_256_GCM_SHA384".into(), "ECDHE-RSA-AES256-GCM-SHA384".into(), "TLS_EMPTY_RENEGOTIATION_INFO_SCSV".into(), "0xabcd".into()));
        let session = Session { cert: Some(der(END)), ..Session::default() };
        let vars = ["i_dn", "s_dn_legacy", "i_dn_legacy", "v_start", "v_end"].map(|v| session.client_var(v));
        assert_eq!(vars, ["CN=int", "/CN=end", "/CN=int", "Nov 22 09:45:34 2026 GMT", "Oct 29 09:45:34 2126 GMT"]);
        assert!(session.client_var("v_remain").parse::<u64>().unwrap() > 36000);
        assert_eq!(Session::default().client_var("i_dn"), "");
    }

    #[test]
    fn sessions_last_for_the_timeout() {
        let timed = Timed((), 10);
        let stamped = Timed::<()>::stamp(b"data");
        assert_eq!(timed.fresh(stamped.clone()), Some(b"data".to_vec()));
        let old = [(now() - 11).to_be_bytes().as_slice(), b"data"].concat();
        assert_eq!((timed.fresh(old), timed.fresh(b"short".to_vec())), (None, None));
        let tickets = Timed(rustls::crypto::ring::Ticketer::new().unwrap(), 10);
        use rustls::server::ProducesTickets;
        assert!(tickets.enabled() && tickets.lifetime() == 10);
        assert_eq!(tickets.decrypt(&tickets.encrypt(b"t").unwrap()), Some(b"t".to_vec()));
    }

    #[test]
    fn passes_data_both_ways_until_closed() {
        let dir = dir();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; ssl_verify_client optional_no_ca; ssl_trusted_certificate c.pem; }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, Path::new("t")).unwrap(), &dir).unwrap());
        assert_eq!(config.servers[0].ssl, [addr]);
        let accepted = std::thread::spawn(move || accept(l.accept().unwrap().0, &config, addr).unwrap());
        let c = dir.join("c.pem");
        let mut client = connect(TcpStream::connect(addr).unwrap(), (addr.ip(), Some("localhost")), Duration::from_secs(5), &client((false, true), Some((&c, &dir.join("k.pem"), None)), None).unwrap()).unwrap();
        let (mut server, session) = accepted.join().unwrap();
        assert_eq!((session.id.len(), session.cipher.as_str(), session.cert.as_ref()), (64, "TLS_AES_256_GCM_SHA384", Some(&der(CERT))));
        assert!(session.ciphers.starts_with("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"), "{}", session.ciphers);
        let session = Session { id: String::new(), cipher: String::new(), ciphers: String::new(), cert: None, ..session };
        assert_eq!(session, Session { protocol: "TLSv1.3".into(), server_name: "localhost".into(), reused: false, verify: "SUCCESS".into(), subject: Some("CN=localhost".into()), ..Session::default() });
        let mut buf = [0u8; 4];
        client.write_all(b"ping").unwrap();
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        // Closing one side ends the stream on the other, which then closes too.
        server.shutdown(Shutdown::Write).unwrap();
        assert_eq!(client.read(&mut buf).unwrap(), 0);
        drop(client);
        assert_eq!(server.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_handshake_that_does_not_end_in_time_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let e = connect(TcpStream::connect(addr).unwrap(), (addr.ip(), None), Duration::from_millis(100), &client((true, false), None, None).unwrap()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        drop(l);
    }

    #[test]
    fn a_failed_handshake_gives_no_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let peer = std::thread::spawn(move || { let mut s = l.accept().unwrap().0; s.write_all(b"HTTP/1.0 400\r\n\r\n").unwrap(); });
        assert!(connect(TcpStream::connect(addr).unwrap(), (addr.ip(), None), Duration::from_secs(5), &client((true, false), None, None).unwrap()).is_err());
        peer.join().unwrap();
    }

    #[test]
    fn keeps_what_it_loaded_as_nginx_does() {
        let dir = dir();
        let (a, b, none) = (dir.join("c.pem"), dir.join("k.pem"), dir.join("none"));
        let (cache, loads) = (CertCache::new(2, 60, 10), std::cell::Cell::new(0));
        let loads = &loads;
        let load = |uncached: bool| move || { loads.set(loads.get() + 1); Ok((Object { chain: Vec::new(), key: None }, uncached)) };
        let (kept, uncached) = (load(false), load(true));
        let fetch = |key, path: &Path, invalidate| { cache.fetch(key, path, invalidate, &kept).unwrap(); loads.get() };
        assert_eq!((fetch(false, &a, false), fetch(false, &a, false)), (1, 1));
        // The key of a file is another object; a third object evicts the least recently used one.
        assert_eq!((fetch(true, &a, false), fetch(false, &b, false), fetch(false, &a, false)), (2, 3, 4));
        assert_eq!(fetch(false, &a, true), 5);
        // After valid seconds, a file that did not change is not loaded again; one that did is.
        cache.nodes.lock().unwrap().last_mut().unwrap().created = 0;
        assert_eq!(fetch(false, &a, false), 5);
        (cache.nodes.lock().unwrap().last_mut().unwrap().created, cache.nodes.lock().unwrap().last_mut().unwrap().file) = (0, (0, 0));
        assert_eq!(fetch(false, &a, false), 6);
        // What must not be kept, or fails to load, is not kept.
        for _ in 0..2 { cache.fetch(false, &none, false, &uncached).unwrap(); }
        assert_eq!(loads.get(), 8);
        assert!(cache.fetch(false, &a, true, &|| Err("failed".into())).is_err());
        assert_eq!(cache.nodes.lock().unwrap().len(), 1);
        // One not used for inactive seconds goes when another comes in.
        cache.nodes.lock().unwrap()[0].accessed = 0;
        fetch(true, &b, false);
        assert_eq!(cache.nodes.lock().unwrap().len(), 1);
    }

    #[test]
    fn loads_the_certificate_for_a_connection() {
        let dir = dir();
        // A key that is not the certificate's.
        std::fs::write(dir.join("other.pem"), "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwQWPnC2Jx/3u3hdA\njGUmqcD72PuhGmag3j4c7dVV64OhRANCAATANLzVnsMiRvhgpGBwTwrnsEsESgL3\nwQJBCIlLunPAFCk9taxLVaqjkHBX5E7184ZLnPSc8ZVLhpB/saEm9hMD\n-----END PRIVATE KEY-----\n").unwrap();
        let (base, cache) = (client((true, false), None, None).unwrap(), CertCache::new(4, 60, 10));
        let (cert, key, other) = (dir.join("c.pem"), dir.join("k.pem"), dir.join("other.pem"));
        assert!(client_cert(&base, (&cert, &key, None), Some(&cache)).is_ok());
        assert!(client_cert(&base, (&cert, &key, None), None).is_ok());
        assert!(client_cert(&base, (&cert, &other, None), Some(&cache)).unwrap_err().starts_with("SSL_use_PrivateKey("));
        assert!(client_cert(&base, (&dir.join("none"), &key, None), None).is_err());
    }
}
