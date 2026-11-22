//! TLS: connections accepted on "listen ... ssl" and connections to proxied
//! servers with "proxy_pass https://". The rest of twinx reads and writes plain
//! HTTP; a thread of each TLS connection passes the decrypted bytes through a
//! Unix socket pair, whose other end twinx uses as it uses a TCP connection.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, Connection, DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection, SignatureScheme};
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

use crate::conf::Config;

/// How long a client has to finish its handshake, as client_header_timeout's default.
const HANDSHAKE: Duration = Duration::from_secs(60);

/// The certificate chain and the private key of ssl_certificate and
/// ssl_certificate_key, in PEM; a key encrypted in PKCS #8 is decrypted with
/// the first of the passwords (each line of ssl_password_file) that does.
pub fn certificate(cert: &Path, key: &Path, passwords: &[String]) -> Result<Arc<CertifiedKey>, String> {
    let chain = certificates(cert)?;
    let encrypted = || std::fs::read_to_string(key).ok().and_then(|pem| pkcs8::Document::from_pem(&pem).ok().and_then(|(_, doc)| { let info = pkcs8::EncryptedPrivateKeyInfo::try_from(doc.as_bytes()).ok()?; passwords.iter().find_map(|p| info.decrypt(p).ok()) }));
    let der = PrivateKeyDer::from_pem_file(key).ok().or_else(|| encrypted().map(|doc| PrivateKeyDer::Pkcs8(doc.as_bytes().to_vec().into())));
    let signing = der.and_then(|k| provider().key_provider.load_private_key(k).ok());
    let signing = signing.ok_or_else(|| format!("cannot load certificate key \"{}\"", key.display()))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

/// The certificates of a PEM file, such as ssl_trusted_certificate.
pub fn certificates(file: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(file).and_then(|certs| certs.collect::<Result<Vec<_>, _>>()).ok().filter(|c| !c.is_empty());
    certs.ok_or_else(|| format!("cannot load certificate \"{}\"", file.display()))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The certificate a client gets on a listening address: that of the server
/// its SNI name selects, as the Host header selects one.
#[derive(Debug)]
struct Sni(Arc<Config>, SocketAddr);

impl ResolvesServerCert for Sni {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        crate::http::server(&self.0, self.1, hello.server_name()).0.certificate.clone()
    }
}

/// What a listening address with "ssl" accepts connections with. Clients
/// are asked for a certificate when a server there has ssl_verify_client, and
/// may send none; theirs is verified once the handshake is done ($ssl_client_verify).
pub fn server(config: Arc<Config>, listen: SocketAddr) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder();
    let builder = if config.servers.iter().any(|s| s.listen.contains(&listen) && s.level.ssl_verify_client) { builder.with_client_cert_verifier(Arc::new(Unverified(provider().signature_verification_algorithms))) } else { builder.with_no_client_auth() };
    Arc::new(builder.with_cert_resolver(Arc::new(Sni(config, listen))))
}

/// What the variables tell of a TLS connection: the protocol ($ssl_protocol,
/// "TLSv1.3"), whether its session was reused ($ssl_session_reused), and the
/// client's certificate: the result of verifying it ($ssl_client_verify) and
/// its subject ($ssl_client_s_dn).
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub protocol: String,
    pub reused: bool,
    pub client_verify: String,
    pub client_s_dn: Option<String>,
}

/// Takes a TLS connection from a client: the handshake, then the plain end of
/// it. The client's certificate is verified against the trusted certificates
/// of the server its SNI name selects.
pub fn accept(mut tcp: TcpStream, tls: &Arc<ServerConfig>, config: &Config, listen: SocketAddr) -> Option<(TcpStream, Session)> {
    let mut conn: Connection = ServerConnection::new(tls.clone()).ok()?.into();
    let mut session = handshake(&mut tcp, &mut conn, HANDSHAKE).ok()?;
    let Connection::Server(server) = &conn else { return None };
    if let Some(chain) = server.peer_certificates() {
        let trusted = &crate::http::server(config, listen, server.server_name()).0.trusted;
        let leaf = X509Certificate::from_der(&chain[0]).ok()?.1;
        (session.client_verify, session.client_s_dn) = (verify(&leaf, trusted), Some(rfc2253(leaf.subject())));
    }
    Some((pipe(tcp, conn).ok()?, session))
}

/// $ssl_client_verify of a client certificate: SUCCESS when a trusted
/// certificate issued it, it is valid now and may be used by clients, or else
/// the first reason it fails, as OpenSSL says it.
fn verify(leaf: &X509Certificate, trusted: &[CertificateDer]) -> String {
    let issued = |der: &CertificateDer| X509Certificate::from_der(der).is_ok_and(|(_, ca)| ca.subject() == leaf.issuer() && leaf.verify_signature(Some(ca.public_key())).is_ok());
    let (untrusted, now, validity) = (!trusted.iter().any(issued), x509_parser::time::ASN1Time::now(), leaf.validity());
    // Without an extended key usage, a certificate may be used for anything.
    let purpose = leaf.extended_key_usage().ok().flatten().is_none_or(|e| e.value.client_auth || e.value.any);
    let errors = [
        (untrusted && leaf.subject() == leaf.issuer(), "self-signed certificate"),
        (untrusted, "unable to get local issuer certificate"),
        (validity.not_before > now, "certificate is not yet valid"),
        (validity.not_after < now, "certificate has expired"),
        (!purpose, "unsupported certificate purpose"),
    ];
    errors.iter().find(|e| e.0).map_or_else(|| "SUCCESS".into(), |e| format!("FAILED:{}", e.1))
}

/// A name as RFC 2253 writes it: the last RDN first, "," between them.
fn rfc2253(name: &X509Name) -> String {
    let registry = x509_parser::objects::oid_registry();
    let escape = |v: &str| v.chars().enumerate().map(|(i, c)| if ",+\"\\<>;".contains(c) || i == 0 && "# ".contains(c) || i + 1 == v.chars().count() && c == ' ' { format!("\\{c}") } else { c.to_string() }).collect::<String>();
    let attr = |a: &x509_parser::x509::AttributeTypeAndValue| format!("{}={}", x509_parser::objects::oid2abbrev(a.attr_type(), registry).map(str::to_string).unwrap_or_else(|_| a.attr_type().to_id_string()), escape(a.as_str().unwrap_or_default()));
    let rdns: Vec<_> = name.iter_rdn().map(|rdn| rdn.iter().map(attr).collect::<Vec<_>>().join("+")).collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(",")
}

/// The certificate of proxy_ssl_certificate, sent to proxied servers that ask for one.
#[derive(Debug)]
struct ClientCertificate(Arc<CertifiedKey>);

impl ResolvesClientCert for ClientCertificate {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A proxied server's certificate is not verified, as with proxy_ssl_verify
/// off, nor is a client's while the handshake goes on; the handshake's
/// signatures are.
#[derive(Debug)]
struct Unverified(WebPkiSupportedAlgorithms);

impl ClientCertVerifier for Unverified {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls12_signature(m, c, d, &self.0) }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
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

/// Connects to a proxied server over TLS without SNI, as proxy_ssl_server_name
/// off does, reusing the sessions of earlier connections to it when
/// proxy_ssl_session_reuse is on, and presenting the certificate of
/// proxy_ssl_certificate if there is one; the plain end of the connection, or
/// the error the handshake failed with (WouldBlock once the timeout passed).
pub fn connect(mut tcp: TcpStream, peer: IpAddr, timeout: Duration, reuse: bool, certificate: Option<&Arc<CertifiedKey>>) -> std::io::Result<TcpStream> {
    // One configuration, with its session cache, for each certificate and reuse.
    static CLIENTS: OnceLock<std::sync::Mutex<Vec<(Option<Arc<CertifiedKey>>, bool, Arc<ClientConfig>)>>> = OnceLock::new();
    let mut clients = CLIENTS.get_or_init(Default::default).lock().unwrap();
    let same = |c: &Option<Arc<CertifiedKey>>| c.as_ref().map(Arc::as_ptr) == certificate.map(Arc::as_ptr);
    let config = match clients.iter().find(|(c, r, _)| same(c) && *r == reuse) { Some((.., config)) => config.clone(), None => {
        let verifier = Arc::new(Unverified(provider().signature_verification_algorithms));
        let builder = ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier);
        let mut c = match certificate { Some(cert) => builder.with_client_cert_resolver(Arc::new(ClientCertificate(cert.clone()))), None => builder.with_no_client_auth() };
        c.enable_sni = false;
        if !reuse { c.resumption = rustls::client::Resumption::disabled(); }
        clients.push((certificate.cloned(), reuse, Arc::new(c)));
        clients[clients.len() - 1].2.clone()
    } };
    drop(clients);
    let mut conn = ClientConnection::new(config, ServerName::from(peer)).map_err(std::io::Error::other)?.into();
    handshake(&mut tcp, &mut conn, timeout)?;
    pipe(tcp, conn)
}

/// Completes the handshake; what the variables tell of it.
fn handshake(tcp: &mut TcpStream, tls: &mut Connection, timeout: Duration) -> std::io::Result<Session> {
    let _ = tcp.set_read_timeout(Some(timeout));
    while tls.is_handshaking() { tls.complete_io(tcp)?; }
    let _ = tcp.set_read_timeout(None);
    let protocol = tls.protocol_version().map(|v| format!("{v:?}").replace('_', ".")).unwrap_or_default();
    Ok(Session { protocol, reused: tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed), client_verify: "NONE".into(), client_s_dn: None })
}

/// Passes data between the TLS connection and one end of a socket pair in a
/// thread of its own, and gives the other end, on which twinx reads and
/// writes as on a TCP connection.
fn pipe(tcp: TcpStream, tls: Connection) -> std::io::Result<TcpStream> {
    let (ours, theirs) = UnixStream::pair()?;
    std::thread::spawn(move || pump(tcp, tls, theirs));
    // SAFETY: the descriptor is a connected stream socket that nothing else owns; the
    // calls twinx makes on a TcpStream (read, write, shutdown, timeouts, poll) work on it.
    Ok(unsafe { TcpStream::from_raw_fd(ours.into_raw_fd()) })
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

    /// KEY encrypted in PKCS #8 with AES-128-CBC and the password "secret".
    const ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjA3nM0dkif/AICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEHciQAzQZKuquPpwIuaQsOkEgZDC
QhRMsYVER/rF/gLqtcXGQ5erct8vT5qppCTRO7dBlVIKcIfoaz6Uz41O7nhJDqYD
vb5OrPSG80BfuG5fg4BC2Jtlltl0O2QUfKJis4wBjxvd0vQqgnjvPHyNLhuB66Wo
hnVEufbzwxasPnXOCEp7Bi6cDtGQgKPJSAPji2+eGabpNmMDjpwdHGKVFUZsx6o=
-----END ENCRYPTED PRIVATE KEY-----
";

    /// A certificate of KEY for CN=server that may only be used by servers (extendedKeyUsage serverAuth).
    const SERVER_ONLY: &str = "-----BEGIN CERTIFICATE-----
MIIBjzCCATSgAwIBAgIUfJGHw8ReKaFt2zSPrqnSsdmdrfYwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGc2VydmVyMCAXDTI2MTEyMjA3NDYyOFoYDzIxMjYxMDI5MDc0
NjI4WjARMQ8wDQYDVQQDDAZzZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQV8MnIDQbB8/uMHXJwABFJKcRsUCxXPNBj+/rwm0WoMqtlMzej/znJb0K03rUC
X+VpEXgEh09RKGvdwPekFRxUo2gwZjAdBgNVHQ4EFgQU309aNfa5jPXn4RFv+yUF
xPorPDEwHwYDVR0jBBgwFoAU309aNfa5jPXn4RFv+yUFxPorPDEwDwYDVR0TAQH/
BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNJADBGAiEA
oMi4rCdCm7s9n0tLIkcBy78enlDvLU+XSghFE8C3WKMCIQCHvwVjS/WZmckk/vVc
oh1UQJsth78VXz9gEzZ9U2lSDQ==
-----END CERTIFICATE-----
";

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("twinx-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("c.pem"), CERT).unwrap();
        std::fs::write(dir.join("k.pem"), KEY).unwrap();
        std::fs::write(dir.join("e.pem"), ENCRYPTED).unwrap();
        dir
    }

    #[test]
    fn loads_certificates() {
        let dir = dir();
        assert_eq!(certificate(&dir.join("c.pem"), &dir.join("k.pem"), &[]).unwrap().cert.len(), 1);
        assert_eq!(certificate(&dir.join("none"), &dir.join("k.pem"), &[]).unwrap_err(), format!("cannot load certificate \"{}\"", dir.join("none").display()));
        assert_eq!(certificate(&dir.join("c.pem"), &dir.join("c.pem"), &[]).unwrap_err(), format!("cannot load certificate key \"{}\"", dir.join("c.pem").display()));
    }

    #[test]
    fn decrypts_keys_with_the_first_password_that_does() {
        let dir = dir();
        let passwords = ["wrong".to_string(), "secret".to_string()];
        assert_eq!(certificate(&dir.join("c.pem"), &dir.join("e.pem"), &passwords).unwrap().cert.len(), 1);
        assert!(certificate(&dir.join("c.pem"), &dir.join("e.pem"), &passwords[..1]).is_err());
    }

    #[test]
    fn verifies_client_certificates_with_the_trusted_ones() {
        let der = certificates(&dir().join("c.pem")).unwrap();
        let leaf = X509Certificate::from_der(&der[0]).unwrap().1;
        assert_eq!(verify(&leaf, &der), "SUCCESS");
        assert_eq!(verify(&leaf, &[]), "FAILED:self-signed certificate");
        assert_eq!(rfc2253(leaf.subject()), "CN=localhost");
        let der = CertificateDer::pem_slice_iter(SERVER_ONLY.as_bytes()).collect::<Result<Vec<_>, _>>().unwrap();
        let leaf = X509Certificate::from_der(&der[0]).unwrap().1;
        assert_eq!(verify(&leaf, &der), "FAILED:unsupported certificate purpose");
    }

    #[test]
    fn writes_names_as_rfc_2253_does() {
        // C=JP, O="a,b", CN=" x": the last RDN first, specials escaped.
        let der = [0x30, 0x2b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'J', b'P', 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x05, b'a', b',', b'b', b'+', b'c', 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, b' ', b'x', b' '];
        let name = X509Name::from_der(&der).unwrap().1;
        assert_eq!(rfc2253(&name), "CN=\\ x\\ ,O=a\\,b\\+c,C=JP");
    }

    #[test]
    fn asks_clients_for_certificates_with_ssl_verify_client() {
        let dir = dir();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; ssl_verify_client optional_no_ca; ssl_trusted_certificate c.pem; }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, Path::new("t")).unwrap(), &dir).unwrap());
        let tls = server(config.clone(), addr);
        let accepted = std::thread::spawn(move || accept(l.accept().unwrap().0, &tls, &config, addr).unwrap().1);
        let cert = certificate(&dir.join("c.pem"), &dir.join("k.pem"), &[]).unwrap();
        let mut client = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5), false, Some(&cert)).unwrap();
        client.write_all(b"x").unwrap();
        let session = accepted.join().unwrap();
        assert_eq!((session.client_verify.as_str(), session.client_s_dn.as_deref()), ("SUCCESS", Some("CN=localhost")));
    }

    #[test]
    fn passes_data_both_ways_until_closed() {
        let dir = dir();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, Path::new("t")).unwrap(), &dir).unwrap());
        assert_eq!(config.servers[0].ssl, [addr]);
        let tls = server(config.clone(), addr);
        let accepted = std::thread::spawn(move || accept(l.accept().unwrap().0, &tls, &config, addr).unwrap());
        let mut client = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5), false, None).unwrap();
        let (mut server, session) = accepted.join().unwrap();
        assert_eq!(session, Session { protocol: "TLSv1.3".into(), reused: false, client_verify: "NONE".into(), client_s_dn: None });
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
        let e = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_millis(100), true, None).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        drop(l);
    }

    #[test]
    fn a_failed_handshake_gives_no_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let peer = std::thread::spawn(move || { let mut s = l.accept().unwrap().0; s.write_all(b"HTTP/1.0 400\r\n\r\n").unwrap(); });
        assert!(connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5), true, None).is_err());
        peer.join().unwrap();
    }
}
