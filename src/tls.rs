use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime};
use x509_parser::asn1_rs::{Any, BitString};
use x509_parser::prelude::{ASN1Time, AlgorithmIdentifier, CertificateRevocationList, FromDer, GeneralName, SubjectPublicKeyInfo, X509Certificate, X509Version};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::conf::Config;
use crate::stream::Stream;

const HANDSHAKE: Duration = Duration::from_secs(60);

fn load(cert: &Path, key: &Path, passwords: Option<&Path>, kept: bool) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    Ok((chain(cert, kept)?, private_key(key, passwords, kept)?.0))
}

pub static INHERITABLE: AtomicBool = AtomicBool::new(true);

static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn new_configuration(inheritable: bool) {
    INHERITABLE.store(inheritable, Ordering::Relaxed);
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

static LOADED: Mutex<Vec<(PathBuf, (i64, u64), u64, Vec<u8>)>> = Mutex::new(Vec::new());

fn read(path: &Path, kept: bool) -> std::io::Result<Vec<u8>> {
    let (generation, mut loaded) = (GENERATION.load(Ordering::Relaxed), LOADED.lock().unwrap());
    if let Some(old) = loaded.iter().find(|l| kept && l.0 == path && l.2 == generation) { return Ok(old.3.clone()) }
    let (meta, inherit) = (file(path), kept && INHERITABLE.load(Ordering::Relaxed));
    if let Some(old) = loaded.iter_mut().find(|l| inherit && l.0 == path && Some(l.1) == meta) { old.2 = generation; return Ok(old.3.clone()) }
    let data = std::fs::read(path)?;
    if let Some(meta) = meta.filter(|_| kept) { loaded.retain(|l| l.0 != path); loaded.push((path.to_path_buf(), meta, generation, data.clone())); }
    Ok(data)
}

fn certificates(pem: &[u8]) -> Option<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let block = block.ok()?;
        if !["CERTIFICATE", "TRUSTED CERTIFICATE"].contains(&block.label.as_str()) { continue }
        let rest = X509Certificate::from_der(&block.contents).ok()?.0.len();
        let rest = if block.label == "CERTIFICATE" { 0 } else { rest };
        certs.push(CertificateDer::from(block.contents[..block.contents.len() - rest].to_vec()));
    }
    Some(certs)
}

fn chain(cert: &Path, kept: bool) -> Result<Vec<CertificateDer<'static>>, String> {
    let chain = read(cert, kept).ok().and_then(|pem| certificates(&pem)).filter(|c| !c.is_empty());
    chain.ok_or_else(|| format!("cannot load certificate \"{}\"", cert.display()))
}

fn private_key(key: &Path, passwords: Option<&Path>, kept: bool) -> Result<(PrivateKeyDer<'static>, bool), String> {
    let text = String::from_utf8(read(key, kept).unwrap_or_default()).unwrap_or_default();
    let passwords = passwords.map(|p| std::fs::read_to_string(p).map_err(|e| format!("open() \"{}\" failed ({e})", p.display()))).transpose()?.unwrap_or_default();
    let encrypted = pkcs8::der::Document::from_pem(&text).ok().filter(|(label, _)| *label == "ENCRYPTED PRIVATE KEY").map(|(_, doc)| doc);
    let decrypt = |doc: &pkcs8::der::Document| passwords.lines().find_map(|p| pkcs8::EncryptedPrivateKeyInfoRef::try_from(doc.as_bytes()).ok()?.decrypt(p).ok());
    let found = match &encrypted { Some(doc) => decrypt(doc).map(|d| PrivateKeyDer::Pkcs8(d.as_bytes().to_vec().into())), None => PrivateKeyDer::from_pem_slice(text.as_bytes()).ok() };
    let found = found.filter(|k| provider().key_provider.load_private_key(k.clone_key()).is_ok());
    Ok((found.ok_or_else(|| format!("cannot load certificate key \"{}\"", key.display()))?, encrypted.is_some()))
}

#[derive(Debug)]
pub struct CertCache {
    max: usize,
    valid: u64,
    inactive: u64,
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

    fn fetch(&self, key: bool, path: &Path, invalidate: bool, create: &dyn Fn() -> Result<(Object, bool), String>) -> Result<Object, String> {
        let (now, mut nodes) = (now(), self.nodes.lock().unwrap());
        if let Some(i) = nodes.iter().position(|n| n.key == key && n.path == path) {
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

    fn expire(&self, nodes: &mut Vec<Node>, mut n: u32, now: u64) {
        while n < 3 && !nodes.is_empty() {
            if n != 0 && now.saturating_sub(nodes[0].accessed) <= self.inactive { return }
            n += 1;
            nodes.remove(0);
        }
    }
}

fn trusted(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read(path, true).map_err(|_| format!("cannot load certificate \"{}\": BIO_new_file() failed", path.display()))?;
    let certs = certificates(&pem).filter(|c| !c.is_empty());
    certs.ok_or_else(|| format!("cannot load certificate \"{}\": PEM_read_bio_X509_AUX() failed", path.display()))
}

fn crls(path: &Path) -> Result<Arc<[Crl]>, String> {
    let pem = read(path, true).map_err(|_| format!("cannot load CRL \"{}\": BIO_new_file() failed", path.display()))?;
    let crls: Option<Vec<Crl>> = CertificateRevocationListDer::pem_slice_iter(&pem).map(|c| c.ok().and_then(|c| Crl::load(&c))).collect();
    crls.filter(|c| !c.is_empty()).map(Arc::from).ok_or_else(|| format!("cannot load CRL \"{}\": PEM_read_bio_X509_CRL() failed", path.display()))
}

#[derive(Debug)]
struct Crl {
    der: Vec<u8>,
    issuer: Vec<u8>,
    next_update: Option<ASN1Time>,
    revoked: HashSet<Vec<u8>>,
}

impl Crl {
    fn load(der: &[u8]) -> Option<Crl> {
        let (_, crl) = CertificateRevocationList::from_der(der).ok()?;
        let revoked = crl.iter_revoked_certificates().map(|r| r.raw_serial().to_vec()).collect();
        Some(Crl { der: der.to_vec(), issuer: crl.issuer().as_raw().to_vec(), next_update: crl.next_update(), revoked })
    }

    fn signed_by(&self, key: &SubjectPublicKeyInfo) -> bool {
        let Ok((_, outer)) = Any::from_der(&self.der) else { return false };
        let Ok((rest, _)) = Any::from_der(outer.data) else { return false };
        let tbs = &outer.data[..outer.data.len() - rest.len()];
        let Ok((rest, algorithm)) = AlgorithmIdentifier::from_der(rest) else { return false };
        let Ok((_, signature)) = BitString::from_der(rest) else { return false };
        x509_parser::verify::verify_signature(key, &algorithm, &signature, tbs).is_ok()
    }
}

/// Keeps a session a TLS 1.3 client resumes, as OpenSSL does; rustls's cache would drop it.
#[derive(Debug)]
struct Kept(Arc<dyn rustls::server::StoresServerSessions>);

impl rustls::server::StoresServerSessions for Kept {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.0.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key)
    }

    fn can_cache(&self) -> bool {
        self.0.can_cache()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    trusted: Vec<CertificateDer<'static>>,
    crls: Option<Arc<[Crl]>>,
    depth: usize,
    named: Option<Named>,
    ocsp: Option<crate::ocsp::Ocsp>,
}

#[derive(Debug, Clone, Copy)]
pub struct Sessions {
    pub tickets: bool,
    pub cache: bool,
    pub shared: bool,
    pub timeout: u64,
}

impl Default for Sessions {
    fn default() -> Sessions {
        Sessions { tickets: true, cache: false, shared: false, timeout: 300 }
    }
}

#[derive(Debug)]
struct Rotated {
    rotate: Option<u64>,
    file: Vec<TicketKey>,
    keys: Mutex<Option<(u64, Arc<dyn rustls::server::ProducesTickets>, Option<Arc<dyn rustls::server::ProducesTickets>>)>>,
}

impl Rotated {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        if let Some(key) = self.file.first() { return key.seal(plain) }
        let mut keys = self.keys.lock().unwrap();
        let now = now();
        if keys.as_ref().is_none_or(|k| now >= k.0) { *keys = Some((self.rotate.map_or(u64::MAX, |t| now + t), rustls::crypto::ring::Ticketer::new().ok()?, keys.take().map(|k| k.1))); }
        keys.as_ref()?.1.encrypt(plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if !self.file.is_empty() { return self.file.iter().find(|k| cipher.starts_with(&k.name))?.open(cipher) }
        let keys = self.keys.lock().unwrap();
        keys.iter().flat_map(|k| std::iter::once(&k.1).chain(&k.2)).find_map(|k| k.decrypt(cipher))
    }
}

#[derive(Debug)]
struct TicketKey {
    name: [u8; 16],
    key: ring::aead::LessSafeKey,
}

impl TicketKey {
    fn load(file: &Path) -> Result<TicketKey, String> {
        let data = std::fs::read(file).map_err(|e| format!("open() \"{}\" failed ({e})", file.display()))?;
        let (alg, key) = match data.len() { 48 => (&ring::aead::AES_128_GCM, &data[16..32]), 80 => (&ring::aead::AES_256_GCM, &data[48..]), _ => return Err(format!("\"{}\" must be 48 or 80 bytes", file.display())) };
        Ok(TicketKey { name: data[..16].try_into().map_err(|_| "short")?, key: ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(alg, key).map_err(|_| "bad key")?) })
    }

    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; 12];
        provider().secure_random.fill(&mut nonce).ok()?;
        let mut sealed = plain.to_vec();
        self.key.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(self.name), &mut sealed).ok()?;
        Some([&self.name[..], &nonce, &sealed].concat())
    }

    fn open(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let (nonce, sealed) = ticket.get(16..)?.split_at_checked(12)?;
        let mut sealed = sealed.to_vec();
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        Some(self.key.open_in_place(nonce, ring::aead::Aad::from(self.name), &mut sealed).ok()?.to_vec())
    }
}

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

impl rustls::server::ProducesTickets for Timed<Rotated> {
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

#[derive(Debug)]
struct Fixed(Vec<Arc<rustls::sign::CertifiedKey>>, Vec<Option<Arc<Staple>>>);

impl Fixed {
    fn new(keys: Vec<Arc<rustls::sign::CertifiedKey>>) -> Fixed {
        let mut kept: Vec<Arc<rustls::sign::CertifiedKey>> = Vec::new();
        for key in keys {
            match kept.iter_mut().find(|k| k.key.algorithm() == key.key.algorithm()) {
                Some(k) => *k = key,
                None => kept.push(key),
            }
        }
        Fixed(kept, Vec::new())
    }

    fn choose(&self, schemes: &[SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let signs = |scheme: &SignatureScheme| self.0.iter().position(|k| k.key.choose_scheme(&[*scheme]).is_some());
        let i = schemes.iter().find_map(signs).or((!self.0.is_empty()).then_some(0))?;
        Some(self.1.get(i).cloned().flatten().map_or_else(|| self.0[i].clone(), |s| s.key(&self.0[i])))
    }
}

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(&self, hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.choose(hello.signature_schemes())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stapling {
    pub verify: bool,
    pub responder: Option<String>,
    pub file: Option<PathBuf>,
}

#[derive(Debug)]
struct Staple {
    source: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>)>,
    verify: bool,
    state: Mutex<(Option<(Arc<rustls::sign::CertifiedKey>, i64)>, i64, bool)>,
}

impl Staple {
    fn new(key: &rustls::sign::CertifiedKey, stapling: &Stapling, trusted: &[CertificateDer<'static>]) -> Result<Option<Arc<Staple>>, String> {
        if let Some(file) = &stapling.file {
            let response = std::fs::read(file).map_err(|e| format!("BIO_new_file(\"{}\") failed ({e})", file.display()))?;
            let stapled = Arc::new(rustls::sign::CertifiedKey { ocsp: Some(response), ..key.clone() });
            return Ok(Some(Arc::new(Staple { source: None, verify: false, state: Mutex::new((Some((stapled, i64::MAX)), i64::MAX, false)) })));
        }
        let source = crate::ocsp::stapled(&key.cert, trusted, stapling.responder.as_deref());
        if let Some(url) = source.as_ref().map(|s| &s.0).filter(|u| !u.starts_with("http://")) { return Err(format!("invalid URL prefix in OCSP responder \"{url}\" in resolver")) }
        Ok(source.map(|source| Arc::new(Staple { source: Some(source), verify: stapling.verify, state: Mutex::new((None, 0, false)) })))
    }

    fn key(self: &Arc<Self>, key: &Arc<rustls::sign::CertifiedKey>) -> Arc<rustls::sign::CertifiedKey> {
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.lock().unwrap();
        if now >= state.1 && !state.2 {
            state.2 = true;
            let (staple, key) = (self.clone(), key.clone());
            std::thread::spawn(move || staple.refresh(&key));
        }
        state.0.as_ref().filter(|s| s.1 >= now).map_or_else(|| key.clone(), |s| s.0.clone())
    }

    fn refresh(&self, key: &rustls::sign::CertifiedKey) {
        let now = chrono::Utc::now().timestamp();
        let fetched = self.source.as_ref().and_then(|(url, request, id, issuer)| crate::ocsp::staple(url, (request, id, issuer), self.verify, now));
        let mut state = self.state.lock().unwrap();
        state.2 = false;
        let Some((response, next)) = fetched else { state.1 = now + 300; return };
        let valid = next.unwrap_or(i64::MAX);
        state.0 = Some((Arc::new(rustls::sign::CertifiedKey { ocsp: Some(response), ..key.clone() }), valid));
        state.1 = valid.saturating_sub(300).min(now + 3600).max(now + 300);
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub verify: bool,
    pub sessions: Sessions,
    pub compress: bool,
    pub ciphers: Option<String>,
    pub protocols: [bool; 2],
    pub prefer: bool,
    pub curves: Option<String>,
    pub crl: Option<PathBuf>,
    pub depth: usize,
    pub ocsp: Option<crate::ocsp::Ocsp>,
    pub ticket_keys: Vec<PathBuf>,
    pub stapling: Option<Stapling>,
    pub client_ca: Option<PathBuf>,
}

const CIPHER_NAMES: &[(rustls::CipherSuite, &str)] = &[
    (rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    (rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    (rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    (rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384"),
    (rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256"),
    (rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-RSA-CHACHA20-POLY1305"),
];

fn ciphers(list: &str) -> Result<Vec<rustls::SupportedCipherSuite>, String> {
    let all = rustls::crypto::ring::DEFAULT_CIPHER_SUITES;
    let named = |s: &rustls::SupportedCipherSuite, e: &str| ["DEFAULT", "ALL", "HIGH"].contains(&e) || CIPHER_NAMES.iter().any(|n| n.0 == s.suite() && n.1 == e);
    let tls12: Vec<_> = all.iter().filter(|s| s.tls13().is_none() && list.split([':', ' ', ',']).any(|e| named(s, e))).copied().collect();
    if tls12.is_empty() { return Err(format!("SSL_CTX_set_cipher_list(\"{list}\") failed")) }
    Ok(all.iter().filter(|s| s.tls13().is_some()).copied().chain(tls12).collect())
}

#[derive(Debug)]
struct Named {
    files: Vec<(crate::vars::Template, crate::vars::Template)>,
    passwords: Option<PathBuf>,
    cache: Option<Arc<CertCache>>,
}

/// A key that does not match its certificate may come from a cache updated between the two loads.
fn cached<T>((cert, key, passwords): (&Path, &Path, Option<&Path>), cache: Option<&CertCache>, check: &dyn Fn(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) -> Result<T, rustls::Error>) -> Result<Result<T, rustls::Error>, String> {
    let fetch = |key: bool, path: &Path, invalidate: bool, create: &dyn Fn() -> Result<(Object, bool), String>| match cache { Some(c) => c.fetch(key, path, invalidate, create), None => create().map(|o| o.0) };
    let mut invalidate = false;
    loop {
        let chain = fetch(false, cert, invalidate, &|| Ok((Object { chain: chain(cert, false)?, key: None }, false)))?.chain;
        let pkey = fetch(true, key, invalidate, &|| private_key(key, passwords, false).map(|(k, encrypted)| (Object { chain: Vec::new(), key: Some(k) }, encrypted)))?.key;
        let checked = check(chain, pkey.ok_or("no key")?);
        if !invalidate && matches!(checked, Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch))) { invalidate = true; continue }
        return Ok(checked);
    }
}

fn certified(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Arc<rustls::sign::CertifiedKey>, rustls::Error> {
    let certified = rustls::sign::CertifiedKey::from_der(chain, key, &provider())?;
    Ok(Arc::new(rustls::sign::CertifiedKey { key: Arc::new(Told(certified.key.clone())), ..certified }))
}

tokio::task_local! {
    static SIGNED: std::cell::Cell<[Option<SignatureScheme>; 2]>;
}

fn signed(side: usize, scheme: SignatureScheme) {
    let _ = SIGNED.try_with(|s| { let mut both = s.get(); both[side] = Some(scheme); s.set(both) });
}

#[derive(Debug)]
struct Told(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for Told {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        Some(Box::new(ToldSigner(offered.iter().find_map(|s| self.0.choose_scheme(&[*s]))?)))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct ToldSigner(Box<dyn rustls::sign::Signer>);

impl rustls::sign::Signer for ToldSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        signed(0, self.0.scheme());
        self.0.sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

const SIGALGS: &[(u16, &str)] = &[
    (0x0403, "ecdsa_secp256r1_sha256"), (0x0503, "ecdsa_secp384r1_sha384"), (0x0603, "ecdsa_secp521r1_sha512"), (0x0807, "ed25519"), (0x0808, "ed448"),
    (0x0809, "rsa_pss_pss_sha256"), (0x080a, "rsa_pss_pss_sha384"), (0x080b, "rsa_pss_pss_sha512"),
    (0x0804, "rsa_pss_rsae_sha256"), (0x0805, "rsa_pss_rsae_sha384"), (0x0806, "rsa_pss_rsae_sha512"),
    (0x0401, "rsa_pkcs1_sha256"), (0x0501, "rsa_pkcs1_sha384"), (0x0601, "rsa_pkcs1_sha512"), (0x0203, "ecdsa_sha1"), (0x0201, "rsa_pkcs1_sha1"),
];

fn sigalg(scheme: Option<SignatureScheme>) -> String {
    scheme.map(u16::from).map_or_else(String::new, |id| SIGALGS.iter().find(|s| s.0 == id).map_or_else(|| format!("0x{id:04x}"), |s| s.1.to_string()))
}

pub fn server((files, passwords): (&[(&Path, &Path)], Option<&Path>), named: Option<Option<Arc<CertCache>>>, trust: &[&Path], options: Options) -> Result<ServerTls, String> {
    let mut fixed = Vec::new();
    for (cert, key) in files.iter().filter(|_| named.is_none()) {
        let (chain, key) = load(cert, key, passwords, true)?;
        fixed.push(certified(chain, key).map_err(|e| format!("cannot load certificate \"{}\" ({e})", cert.display()))?);
    }
    let template = |p: &Path| crate::vars::Template::parse(&p.to_string_lossy());
    let templates = || files.iter().map(|(c, k)| Ok((template(c)?, template(k)?))).collect::<Result<Vec<_>, String>>();
    let named = named.map(|cache| Ok::<_, String>(Named { files: templates()?, passwords: passwords.map(Path::to_path_buf), cache })).transpose()?;
    let trusted = trust.iter().map(|p| trusted(p)).collect::<Result<Vec<_>, _>>()?.concat();
    let suites = options.ciphers.as_deref().map(ciphers).transpose()?;
    let groups = options.curves.as_deref().map(curves).transpose()?;
    let suites = CryptoProvider { cipher_suites: suites.unwrap_or_else(|| provider().cipher_suites.clone()), kx_groups: groups.unwrap_or_else(|| provider().kx_groups.clone()), ..(*provider()).clone() };
    let versions: Vec<_> = [&rustls::version::TLS12, &rustls::version::TLS13].into_iter().zip(options.protocols).filter_map(|(v, on)| on.then_some(v)).collect();
    let (versions, fixed) = if versions.is_empty() { (vec![&rustls::version::TLS13], Vec::new()) } else { (versions, fixed) };
    let builder = ServerConfig::builder_with_provider(Arc::new(suites)).with_protocol_versions(&versions).map_err(|e| e.to_string())?;
    let builder = if options.verify { builder.with_client_cert_verifier(Arc::new(AnyClient(provider().signature_verification_algorithms, ca_names(options.client_ca.as_deref())?))) } else { builder.with_no_client_auth() };
    let mut fixed = Fixed::new(fixed);
    if let Some(stapling) = &options.stapling { fixed.1 = fixed.0.iter().map(|k| Staple::new(k, stapling, &trusted)).collect::<Result<_, _>>()?; }
    let mut config = builder.with_cert_resolver(Arc::new(fixed));
    config.ignore_client_order = options.prefer;
    config.cert_compressors = if options.compress { vec![rustls::compress::ZLIB_COMPRESSOR] } else { Vec::new() };
    let sessions = options.sessions;
    config.session_storage = if sessions.cache { Arc::new(Kept(rustls::server::ServerSessionMemoryCache::new(20480))) } else { Arc::new(rustls::server::NoServerSessionStorage {}) };
    let file = options.ticket_keys.iter().map(|f| TicketKey::load(f)).collect::<Result<Vec<_>, _>>()?;
    let keys = Rotated { rotate: sessions.shared.then_some(sessions.timeout), file, keys: Mutex::new(None) };
    if sessions.tickets { config.ticketer = Arc::new(Timed(keys, sessions.timeout)); }
    Ok(ServerTls { config: Arc::new(config), trusted, crls: options.crl.as_deref().map(crls).transpose()?, depth: options.depth, named, ocsp: options.ocsp })
}

impl ServerTls {
    fn for_connection(&self, (peer, local): (SocketAddr, SocketAddr), name: &str) -> Option<Arc<ServerConfig>> {
        let Some(n) = &self.named else { return Some(self.config.clone()) };
        let r = crate::vars::Request::connection(peer, local, Some(Arc::new(Session { server_name: name.to_string(), ..Session::default() })));
        let sent = crate::vars::Sent::default();
        let mut keys = Vec::new();
        for (cert, key) in &n.files {
            let (cert, key) = (PathBuf::from(cert.render(&r, &sent)), PathBuf::from(key.render(&r, &sent)));
            keys.push(cached((&cert, &key, n.passwords.as_deref()), n.cache.as_deref(), &certified).ok()?.ok()?);
        }
        let mut config = (*self.config).clone();
        config.cert_resolver = Arc::new(Fixed::new(keys));
        Some(Arc::new(config))
    }
}

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
    pub curve: String,
    pub curves: String,
    pub alpn: String,
    pub sigalg: String,
    pub client_sigalg: String,
}

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

const CURVES: &[(u16, &str)] = &[
    (0x0017, "prime256v1"), (0x0018, "secp384r1"), (0x0019, "secp521r1"), (0x001d, "X25519"), (0x001e, "X448"),
    (0x0100, "ffdhe2048"), (0x0101, "ffdhe3072"), (0x0102, "ffdhe4096"), (0x0103, "ffdhe6144"), (0x0104, "ffdhe8192"),
];

fn curve(id: u16) -> String {
    CURVES.iter().find(|c| c.0 == id).map_or_else(|| format!("0x{id:04x}"), |c| c.1.to_string())
}

fn curves(list: &str) -> Result<Vec<&'static dyn rustls::crypto::SupportedKxGroup>, String> {
    if list == "auto" { return Ok(provider().kx_groups.clone()) }
    let named = |n: &str| rustls::crypto::ring::ALL_KX_GROUPS.iter().copied().find(|g| [curve(u16::from(g.name())), format!("{:?}", g.name())].iter().any(|c| c.eq_ignore_ascii_case(n)) || [("P-256", 0x0017), ("P-384", 0x0018)].contains(&(n, u16::from(g.name()))));
    list.split(':').map(|n| named(n).ok_or_else(|| format!("SSL_CTX_set1_curves_list(\"{list}\") failed"))).collect()
}

fn cipher(id: u16) -> String {
    CIPHERS.iter().find(|c| c.0 == id).map_or_else(|| format!("0x{id:04x}"), |c| c.1.to_string())
}

const ATTRIBUTES: &[(&str, &str)] = &[
    ("2.5.4.3", "CN"), ("2.5.4.4", "SN"), ("2.5.4.5", "serialNumber"), ("2.5.4.6", "C"), ("2.5.4.7", "L"), ("2.5.4.8", "ST"),
    ("2.5.4.9", "street"), ("2.5.4.10", "O"), ("2.5.4.11", "OU"), ("2.5.4.12", "title"), ("2.5.4.17", "postalCode"),
    ("2.5.4.42", "GN"), ("2.5.4.43", "initials"), ("2.5.4.46", "dnQualifier"), ("2.5.4.65", "pseudonym"),
    ("0.9.2342.19200300.100.1.1", "UID"), ("0.9.2342.19200300.100.1.25", "DC"), ("1.2.840.113549.1.9.1", "emailAddress"),
];

fn escape_2253(value: &str) -> String {
    let last = value.len().saturating_sub(1);
    value.bytes().enumerate().map(|(i, c)| match c {
        b',' | b'+' | b'"' | b'\\' | b'<' | b'>' | b';' => format!("\\{}", c as char), 0..0x20 | 0x7f.. => format!("\\{c:02X}"),
        b'#' if i == 0 => "\\#".to_string(),
        b' ' if i == 0 || i == last => "\\ ".to_string(),
        _ => (c as char).to_string(),
    }).collect()
}

fn name(name: &x509_parser::x509::X509Name, legacy: bool) -> String {
    let attr = |a: &x509_parser::x509::AttributeTypeAndValue| {
        let oid = a.attr_type().to_id_string();
        let value = a.as_str().unwrap_or_default();
        format!("{}={}", ATTRIBUTES.iter().find(|t| t.0 == oid).map_or(oid.as_str(), |t| t.1), if legacy { value.to_string() } else { escape_2253(value) })
    };
    if legacy { return name.iter_attributes().map(|a| format!("/{}", attr(a))).collect() }
    let attrs: Vec<(usize, String)> = name.iter_rdn().enumerate().flat_map(|(i, rdn)| rdn.iter().map(move |a| (i, attr(a)))).collect();
    attrs.iter().rev().enumerate().map(|(n, (i, a))| if n == 0 { a.clone() } else { format!("{}{a}", if attrs[attrs.len() - n].0 == *i { "+" } else { "," }) }).collect()
}

pub fn base64(data: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let quad = |c: &[u8]| { let (n, len) = (c.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - c.len())), c.len()); (0..4).map(move |i| if i <= len { DIGITS[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' }) };
    data.chunks(3).flat_map(quad).collect()
}

pub fn escape(text: &str) -> String {
    text.bytes().map(|c| if c.is_ascii_alphanumeric() || b"-._~".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
}

fn pem(der: &[u8]) -> String {
    let base64 = base64(der);
    let lines: Vec<&str> = base64.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).unwrap_or_default()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

impl Session {
    pub fn client_var(&self, var: &str) -> String {
        let Some((_, cert)) = self.cert.as_ref().and_then(|c| x509_parser::parse_x509_certificate(c).ok()) else { return String::new() };
        let time = |t: ASN1Time| chrono::DateTime::from_timestamp(t.timestamp(), 0).map(|t| t.format("%b %e %H:%M:%S %Y GMT").to_string()).unwrap_or_default();
        match var {
            "i_dn" => name(cert.issuer(), false),
            "s_dn_legacy" => name(cert.subject(), true),
            "i_dn_legacy" => name(cert.issuer(), true),
            "serial" => serial(cert.raw_serial()),
            "fingerprint" => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, self.cert.as_deref().unwrap_or_default()).as_ref().iter().map(|b| format!("{b:02x}")).collect(),
            "v_start" => time(cert.validity().not_before),
            "v_end" => time(cert.validity().not_after),
            "raw_cert" => pem(self.cert.as_deref().unwrap_or_default()),
            "escaped_cert" => escape(&pem(self.cert.as_deref().unwrap_or_default())),
            "cert" => { let pem = pem(self.cert.as_deref().unwrap_or_default()); format!("{}\n", pem.trim_end().replace('\n', "\n\t")) }
            _ => ((cert.validity().not_after.timestamp() - now() as i64) / 86400).max(0).to_string(),
        }
    }
}

fn serial(raw: &[u8]) -> String {
    let negative = raw.first().is_some_and(|b| b & 0x80 != 0);
    let mut magnitude = raw.to_vec();
    if negative {
        let mut carry = true;
        for b in magnitude.iter_mut().rev() { (*b, carry) = (!*b).overflowing_add(u8::from(carry)); }
    }
    let first = magnitude.iter().position(|b| *b != 0).unwrap_or(magnitude.len());
    let hex: String = magnitude[first..].iter().map(|b| format!("{b:02X}")).collect();
    format!("{}{}", if negative { "-" } else { "" }, if hex.is_empty() { "00" } else { &hex })
}

pub async fn plain(tcp: &TcpStream) -> Option<bool> {
    let mut first = [0];
    let n = tokio::time::timeout(HANDSHAKE, tcp.peek(&mut first)).await.ok()?.ok()?;
    Some(n == 1 && first[0] != 0x16 && first[0] & 0x80 == 0)
}

pub async fn accept(tcp: TcpStream, config: &Config, listen: SocketAddr) -> Option<(Stream, Session)> {
    let addrs = (tcp.peer_addr().ok()?, tcp.local_addr().ok()?);
    let taken = async { (tokio::time::timeout(HANDSHAKE, handshake(tcp, config, listen, addrs)).await.ok().flatten(), SIGNED.with(std::cell::Cell::get)) };
    let (taken, [server, client]) = SIGNED.scope(std::cell::Cell::new([None; 2]), taken).await;
    let (stream, tls, mut session) = taken?;
    (session.sigalg, session.client_sigalg) = (sigalg(server), sigalg(client));
    let chain = stream.get_ref().1.peer_certificates().map(<[_]>::to_vec).unwrap_or_default();
    // An OCSP responder is asked over the network, which may take long, so not on the event loop.
    session.verify = match tls.ocsp.clone().filter(|_| !chain.is_empty()) {
        Some(ocsp) => {
            let (chain, trusted, crls, depth) = (chain.clone(), tls.trusted.clone(), tls.crls.clone(), tls.depth);
            tokio::task::spawn_blocking(move || verified(&chain, (&trusted, crls.as_deref(), depth), Some(&ocsp))).await.ok()?
        }
        None => verified(&chain, (&tls.trusted, tls.crls.as_deref(), tls.depth), None),
    };
    (session.subject, session.cert) = (chain.first().and_then(|c| subject(c)), chain.first().cloned());
    Some((Stream::Server(Box::new(stream)), session))
}

fn sni(records: &[u8]) -> Option<String> {
    let (mut msg, mut rest) = (Vec::new(), records);
    while let [0x16, _, _, hi, lo, more @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        msg.extend_from_slice(more.get(..len)?);
        rest = &more[len..];
    }
    let take = |at: &mut usize, n: usize| { let part = msg.get(*at..*at + n); *at += n; part };
    let u16_at = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    let mut at = 4 + 2 + 32;
    let n = usize::from(*take(&mut at, 1)?.first()?); take(&mut at, n)?;
    let n = u16_at(take(&mut at, 2)?); take(&mut at, n)?;
    let n = usize::from(*take(&mut at, 1)?.first()?); take(&mut at, n)?;
    let end = u16_at(take(&mut at, 2)?) + at;
    while at + 4 <= end {
        let (kind, len) = (u16_at(take(&mut at, 2)?), u16_at(take(&mut at, 2)?));
        let ext = take(&mut at, len)?;
        if let (0, [_, _, 0, hi, lo, name @ ..]) = (kind, ext) { return name.get(..u16_at(&[*hi, *lo])).map(|n| String::from_utf8_lossy(n).into_owned()) }
    }
    None
}

async fn handshake<'a>(mut tcp: TcpStream, config: &'a Config, listen: SocketAddr, addrs: (SocketAddr, SocketAddr)) -> Option<(tokio_rustls::server::TlsStream<TcpStream>, &'a ServerTls, Session)> {
    let (mut acceptor, mut buf) = (rustls::server::Acceptor::default(), Vec::new());
    let mut came = Vec::new();
    let accepted = loop {
        buf.clear();
        if crate::stream::read_into(&mut tcp, &mut buf, None).await == 0 { return None }
        came.extend_from_slice(&buf);
        let mut data = &buf[..];
        while !data.is_empty() { if acceptor.read_tls(&mut data).ok()? == 0 { break } }
        if let Some(accepted) = acceptor.accept().ok()? { break accepted }
    };
    let hello = accepted.client_hello();
    // rustls gives the name in lower case and not at all for an address; $ssl_server_name is the name as sent.
    let sent = sni(&came);
    let chosen = sent.as_deref().map(|n| n.strip_suffix('.').unwrap_or(n).to_ascii_lowercase());
    let name = hello.server_name().map(str::to_string).or_else(|| chosen.clone()).unwrap_or_default();
    let server = crate::http::server(config, listen, chosen.as_deref().or(hello.server_name())).0;
    if server.level.ssl_reject_handshake { let _ = tcp.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70]).await; return None }
    let tls = server.tls.as_ref().or(crate::http::default_server(config, listen).tls.as_ref())?;
    let ciphers = hello.cipher_suites().iter().map(|c| cipher(u16::from(*c))).collect::<Vec<_>>().join(":");
    let curves = hello.named_groups().unwrap_or_default().iter().map(|g| curve(u16::from(*g))).collect::<Vec<_>>().join(":");
    let mut for_connection = (*tls.for_connection(addrs, &name)?).clone();
    let h2 = crate::http::http2(config, listen, server).then_some(&b"h2"[..]);
    for_connection.alpn_protocols = h2.into_iter().chain([&b"http/1.1"[..], b"http/1.0", b"http/0.9"]).map(<[u8]>::to_vec).collect();
    let mut id = None;
    let start = tokio_rustls::StartHandshake::from_parts(accepted, tcp);
    let stream = start.into_stream_with(Arc::new(for_connection), |conn| {
        let mut new = [0u8; 32];
        id = conn.received_resumption_data().map(<[u8]>::to_vec).or_else(|| provider().secure_random.fill(&mut new).ok().map(|()| new.to_vec()));
        conn.set_resumption_data(id.as_deref().unwrap_or_default());
    }).await.ok()?;
    let id = id?;
    let conn = stream.get_ref().1;
    let protocol = conn.protocol_version().map(|v| format!("{v:?}").replace('_', ".")).unwrap_or_default();
    let cipher = conn.negotiated_cipher_suite().map(|c| cipher(u16::from(c.suite()))).unwrap_or_default();
    let curve = conn.negotiated_key_exchange_group().map(|g| curve(u16::from(g.name()))).unwrap_or_default();
    let reused = conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
    let alpn = String::from_utf8_lossy(conn.alpn_protocol().unwrap_or_default()).into_owned();
    let id = id.iter().map(|b| format!("{b:02x}")).collect();
    Some((stream, tls, Session { protocol, server_name: sent.unwrap_or(name), reused, id, cipher, ciphers, curve, curves, alpn, ..Session::default() }))
}

#[derive(Debug)]
struct AnyClient(WebPkiSupportedAlgorithms, Vec<DistinguishedName>);

fn ca_names(file: Option<&Path>) -> Result<Vec<DistinguishedName>, String> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for cert in file.map(trusted).transpose()?.unwrap_or_default() {
        let name = X509Certificate::from_der(&cert).map_err(|e| e.to_string())?.1.subject().as_raw().to_vec();
        if !names.contains(&name) { names.push(name) }
    }
    Ok(names.into_iter().map(DistinguishedName::from).collect())
}

impl ClientCertVerifier for AnyClient {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.1
    }

    fn verify_client_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    // Only a client that does not take TLS 1.3 has this called.
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed(1, dss.scheme);
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed(1, dss.scheme);
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = self.0.supported_schemes();
        schemes.sort_by_key(|s| SIGALGS.iter().position(|a| a.0 == u16::from(*s)).unwrap_or(usize::MAX));
        schemes
    }
}

fn verified(chain: &[CertificateDer<'static>], (trusted, crls, depth): (&[CertificateDer<'static>], Option<&[Crl]>, usize), ocsp: Option<&crate::ocsp::Ocsp>) -> String {
    let Some(leaf) = chain.first() else { return "NONE".to_string() };
    let checked = verify_chain(leaf, &chain[1..], trusted, crls, depth, true).and_then(|certs| ocsp.map_or(Ok(()), |o| o.check(&certs)));
    checked.map_or_else(|e| format!("FAILED:{e}"), |()| "SUCCESS".to_string())
}

fn subject(der: &[u8]) -> Option<String> {
    Some(name(x509_parser::parse_x509_certificate(der).ok()?.1.subject(), false))
}

#[derive(Debug)]
struct Proxied(WebPkiSupportedAlgorithms, Option<Verify>);

impl ServerCertVerifier for Proxied {
    fn verify_server_cert(&self, end: &CertificateDer, sent: &[CertificateDer], name: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        self.1.as_ref().map_or(Ok(()), |v| v.check(end, sent, name))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls12_signature(m, c, d, &self.0) }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[derive(Debug)]
pub struct Verify {
    trusted: Vec<CertificateDer<'static>>,
    crls: Option<Arc<[Crl]>>,
    depth: usize,
}

pub fn verify(trust: Option<&Path>, crl: Option<&Path>, depth: usize) -> Result<Verify, String> {
    Ok(Verify { trusted: trust.map(trusted).transpose()?.unwrap_or_default(), crls: crl.map(crls).transpose()?, depth })
}

impl Verify {
    fn check(&self, end: &CertificateDer, sent: &[CertificateDer], name: &ServerName) -> Result<(), rustls::Error> {
        let name = match name { ServerName::IpAddress(ip) => IpAddr::from(*ip).to_string(), n => n.to_str().into_owned() };
        let chain = verify_chain(end, sent, &self.trusted, self.crls.as_deref(), self.depth, false).map_err(|e| rustls::Error::General(format!("upstream SSL certificate verify error: ({e})")))?;
        for_name(&chain[0], &name).then_some(()).ok_or_else(|| rustls::Error::General(format!("upstream SSL certificate does not match \"{name}\"")))
    }
}

fn verify_chain<'a>(end: &'a [u8], sent: &'a [CertificateDer], trusted: &'a [CertificateDer], crls: Option<&'a [Crl]>, depth: usize, last: bool) -> Result<Vec<X509Certificate<'a>>, &'static str> {
    let parse = |d: &'a [u8]| X509Certificate::from_der(d).ok().map(|(_, c)| c);
    let (anchors, sent): (Vec<_>, Vec<_>) = (trusted.iter().filter_map(|d| parse(d)).collect(), sent.iter().filter_map(|d| parse(d)).collect());
    let mut chain = vec![parse(end).ok_or("unable to decode certificate")?];
    let is_trusted = |c: &X509Certificate| trusted.iter().any(|t| t.as_ref() == c.as_raw());
    loop {
        let cur = chain.last().unwrap();
        let self_signed = cur.subject().as_raw() == cur.issuer().as_raw();
        if self_signed && is_trusted(cur) { break }
        let issued = |c: &&X509Certificate<'a>| c.subject().as_raw() == cur.issuer().as_raw() && cur.verify_signature(Some(c.public_key())).is_ok();
        let issuer = if self_signed || chain.len() > depth + 1 { None } else { anchors.iter().find(issued).or_else(|| sent.iter().find(issued)) };
        let Some(issuer) = issuer.cloned() else {
            let alone = if chain.len() == 1 { "self-signed certificate" } else { "self-signed certificate in certificate chain" };
            if !self_signed && last && chain.len() == 1 { return Err("unable to verify the first certificate") }
            return Err(if self_signed { alone } else if chain.iter().any(is_trusted) { "unable to get issuer certificate" } else { "unable to get local issuer certificate" });
        };
        chain.push(issuer);
    }
    let mut errors = Vec::new();
    let purpose = |c: &&X509Certificate| c.extended_key_usage().ok().flatten().is_some_and(|u| !if last { u.value.client_auth } else { u.value.server_auth });
    if chain.iter().filter(|c| !is_trusted(c)).any(|c| purpose(&c)) { errors.push("unsuitable certificate purpose") }
    if chain[1..].iter().any(|c| !c.is_ca() && c.version() != X509Version::V1) { errors.push("invalid CA certificate") }
    for (i, c) in chain.iter().enumerate().filter(|_| crls.is_some()) {
        let issuer = chain.get(i + 1).unwrap_or(c);
        let Some(crl) = crls.into_iter().flatten().find(|l| l.issuer == c.issuer().as_raw() && l.signed_by(issuer.public_key())) else { errors.push("unable to get certificate CRL"); continue };
        if crl.next_update.is_some_and(|t| t < ASN1Time::now()) { errors.push("CRL has expired") }
        if crl.revoked.contains(c.raw_serial()) { errors.push("certificate revoked") }
    }
    errors.extend(chain.iter().rev().filter(|c| !c.validity().is_valid()).map(|c| if c.validity().not_before > ASN1Time::now() { "certificate is not yet valid" } else { "certificate has expired" }));
    match if last { errors.last() } else { errors.first() } { Some(e) => Err(e), None => Ok(chain) }
}

fn for_name(cert: &X509Certificate, name: &str) -> bool {
    let names = cert.subject_alternative_name().ok().flatten().map(|e| e.value.general_names.clone()).unwrap_or_default();
    let mut dns: Vec<&str> = names.iter().filter_map(|g| if let GeneralName::DNSName(d) = g { Some(*d) } else { None }).collect();
    if dns.is_empty() { dns.extend(cert.subject().iter_common_name().last().and_then(|a| a.as_str().ok())); }
    dns.iter().any(|p| host_matches(p, name))
}

fn host_matches(pattern: &str, name: &str) -> bool {
    let (Some((p, rest)), Some((n, nrest))) = (pattern.split_once('.'), name.split_once('.')) else { return pattern.eq_ignore_ascii_case(name) };
    let Some((pre, post)) = p.split_once('*').filter(|(_, post)| rest.contains('.') && !post.contains('*')) else { return pattern.eq_ignore_ascii_case(name) };
    let n = n.as_bytes();
    rest.eq_ignore_ascii_case(nrest) && n.len() >= (pre.len() + post.len()).max(1) && n[..pre.len()].eq_ignore_ascii_case(pre.as_bytes()) && n[n.len() - post.len()..].eq_ignore_ascii_case(post.as_bytes())
}

pub fn client((reuse, sni, protocols): (bool, bool, [bool; 2]), cert: Option<(&Path, &Path, Option<&Path>)>, verify: Option<Verify>) -> Result<Arc<ClientConfig>, String> {
    let builder = proxied(verify, protocols)?;
    let mut c = match cert.map(|(c, k, p)| load(c, k, p, true)).transpose()? {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };
    c.enable_sni = sni;
    if !reuse { c.resumption = rustls::client::Resumption::disabled(); }
    Ok(Arc::new(c))
}

fn proxied(verify: Option<Verify>, protocols: [bool; 2]) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>, String> {
    let verifier = Arc::new(Proxied(provider().signature_verification_algorithms, verify));
    let versions: Vec<_> = [&rustls::version::TLS12, &rustls::version::TLS13].into_iter().zip(protocols).filter_map(|(v, on)| on.then_some(v)).collect();
    Ok(ClientConfig::builder_with_provider(provider()).with_protocol_versions(&versions).map_err(|e| e.to_string())?.dangerous().with_custom_certificate_verifier(verifier))
}

pub fn client_cert(base: &Arc<ClientConfig>, files: (&Path, &Path, Option<&Path>), cache: Option<&CertCache>) -> Result<Arc<ClientConfig>, String> {
    let config = cached(files, cache, &|chain, pkey| proxied(None, [true, true]).expect("TLS 1.2 and 1.3 are both had").with_client_auth_cert(chain, pkey))?;
    let mut c = (**base).clone();
    c.client_auth_cert_resolver = config.map_err(|e| format!("SSL_use_PrivateKey(\"{}\") failed ({e})", files.1.display()))?.client_auth_cert_resolver;
    Ok(Arc::new(c))
}

pub fn h2(config: &Arc<ClientConfig>) -> Arc<ClientConfig> {
    let mut c = (**config).clone();
    c.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(c)
}

pub async fn connect(tcp: TcpStream, (peer, name): (IpAddr, Option<&str>), timeout: Duration, config: &Arc<ClientConfig>) -> std::io::Result<Stream> {
    let name = name.map_or(Ok(ServerName::from(peer)), |n| ServerName::try_from(n.to_string()).map_err(std::io::Error::other))?;
    match tokio::time::timeout(timeout, tokio_rustls::TlsConnector::from(config.clone()).connect(name, tcp)).await {
        Ok(stream) => stream.map(|s| Stream::Client(Box::new(s))),
        Err(_) => Err(std::io::ErrorKind::WouldBlock.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_of_client_hellos() {
        let ext = |name: &[u8]| { let mut e = vec![0, 0]; let list = [&[0u8][..], &(name.len() as u16).to_be_bytes(), name].concat(); e.extend((list.len() as u16 + 2).to_be_bytes()); e.extend((list.len() as u16).to_be_bytes()); e.extend(list); e };
        let hello = |exts: Vec<u8>| {
            let body = [&[3u8, 3][..], &[0; 32], &[0], &[0, 2, 0x13, 1], &[1, 0], &(exts.len() as u16).to_be_bytes(), &exts].concat();
            let msg = [&[1u8, 0][..], &(body.len() as u16).to_be_bytes(), &body].concat();
            let (a, b) = msg.split_at(10);
            [&[0x16u8, 3, 1][..], &(a.len() as u16).to_be_bytes(), a, &[0x16, 3, 1], &(b.len() as u16).to_be_bytes(), b].concat()
        };
        assert_eq!(sni(&hello([&[0u8, 23, 0, 0][..], &ext(b"SeCond.")].concat())).as_deref(), Some("SeCond."));
        assert_eq!(sni(&hello(ext(b"127.0.0.1"))).as_deref(), Some("127.0.0.1"));
        assert_eq!(sni(&hello(Vec::new())), None);
        assert_eq!(sni(&hello(ext(b"x"))[..20]), None);
    }

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

    fn crl(pem: &str) -> Crl {
        Crl::load(&CertificateRevocationListDer::from_pem_slice(pem.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn verifies_chains_as_openssl() {
        let (root, int, end) = (der(ROOT), der(INT), der(END));
        let ok = |sent: &[CertificateDer<'static>], trusted: &[CertificateDer<'static>], crls: Option<&[Crl]>, depth| verify_chain(&end, sent, trusted, crls, depth, false).map(|_| ());
        assert_eq!(ok(&[int.clone()], &[root.clone()], None, 2), Ok(()));
        assert_eq!(ok(&[int.clone()], &[root.clone()], None, 1), Ok(()));
        assert_eq!(ok(&[int.clone()], &[root.clone()], None, 0), Err("unable to get local issuer certificate"));
        assert_eq!(ok(&[], &[root.clone()], None, 2), Err("unable to get local issuer certificate"));
        assert_eq!(verify_chain(&end, &[], &[root.clone()], None, 2, true).map(|_| ()), Err("unable to verify the first certificate"));
        assert_eq!(verify_chain(&end, &[int.clone()], &[], None, 2, true).map(|_| ()), Err("unable to get local issuer certificate"));
        assert_eq!(ok(&[], &[int.clone(), root.clone()], None, 1), Ok(()));
        assert_eq!(ok(&[], &[int.clone(), root.clone()], None, 0), Err("unable to get issuer certificate"));
        assert_eq!(ok(&[], &[int.clone()], None, 2), Err("unable to get issuer certificate"));
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(ROOT_CRL)]), 2), Err("unable to get certificate CRL"));
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(ROOT_CRL), crl(INT_CRL)]), 2), Ok(()));
        assert_eq!(ok(&[int.clone()], &[root.clone()], Some(&[crl(REVOKED_CRL), crl(INT_CRL)]), 2), Err("certificate revoked"));
        let last = |crls: &[Crl]| verified(&[end.clone(), int.clone()], (std::slice::from_ref(&root), Some(crls), 2), None);
        assert_eq!(last(&[crl(REVOKED_CRL)]), "FAILED:certificate revoked");
        assert_eq!(last(&[crl(ROOT_CRL)]), "FAILED:unable to get certificate CRL");
        assert_eq!(last(&[crl(ROOT_CRL), crl(INT_CRL)]), "SUCCESS");
        assert!(verify_chain(&root, &[], &[root.clone()], None, 0, false).is_ok());
        assert_eq!(verify_chain(&root, &[], &[], None, 0, false).map(|_| ()), Err("self-signed certificate"));
        assert_eq!(verify_chain(&int, &[root.clone()], &[], None, 1, false).map(|_| ()), Err("self-signed certificate in certificate chain"));
    }

    #[test]
    fn writes_serials_as_openssl() {
        for (raw, text) in [(&[0x01][..], "01"), (&[0x00, 0x80], "80"), (&[0xff, 0x01], "-FF"), (&[0x80], "-80"), (&[0x00], "00"), (&[0xff], "-01"), (&[0x01, 0x23, 0xab], "0123AB")] {
            assert_eq!(serial(raw), text, "{raw:02x?}");
        }
    }

    #[test]
    fn escapes_names_as_rfc_2253() {
        assert_eq!(escape_2253("d\"e;f<g>h"), "d\\\"e\\;f\\<g\\>h");
        assert_eq!(escape_2253("a, b+c"), "a\\, b\\+c");
        assert_eq!(escape_2253(" a#b "), "\\ a#b\\ ");
        assert_eq!(escape_2253("#c\\"), "\\#c\\\\");
        assert_eq!(escape_2253("\u{e9}\n"), "\\C3\\A9\\0A");
        assert_eq!(escape_2253(""), "");
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
    fn sigalgs() {
        assert_eq!(sigalg(None), "");
        assert_eq!(sigalg(Some(SignatureScheme::RSA_PSS_SHA256)), "rsa_pss_rsae_sha256");
        assert_eq!(sigalg(Some(SignatureScheme::ED25519)), "ed25519");
        assert_eq!(sigalg(Some(SignatureScheme::Unknown(0x0102))), "0x0102");
        let asked = AnyClient(provider().signature_verification_algorithms, Vec::new()).supported_verify_schemes();
        assert_eq!(asked[..2], [SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ECDSA_NISTP384_SHA384]);
        assert!(asked.iter().position(|s| *s == SignatureScheme::RSA_PSS_SHA256) < asked.iter().position(|s| *s == SignatureScheme::RSA_PSS_SHA512));
        signed(0, SignatureScheme::ED25519);
    }

    #[test]
    fn resumed_sessions_are_kept() {
        use rustls::server::StoresServerSessions;
        let kept = Kept(rustls::server::ServerSessionMemoryCache::new(4));
        assert!(kept.can_cache() && kept.put(b"id".to_vec(), b"session".to_vec()));
        for _ in 0..3 { assert_eq!(kept.take(b"id").as_deref(), Some(&b"session"[..])); }
        assert_eq!(kept.get(b"id").as_deref(), Some(&b"session"[..]));
        assert!(kept.take(b"other").is_none());
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
        assert!(verify(None, Some(&dir.join("none")), 1).unwrap_err().starts_with("cannot load CRL \""));
        assert!(verify(Some(&dir.join("none")), None, 1).unwrap_err().ends_with("\": BIO_new_file() failed"));
        std::fs::write(dir.join("empty"), "").unwrap();
        std::fs::write(dir.join("broken"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
        std::fs::write(dir.join("broken.crl"), "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n").unwrap();
        for file in ["empty", "broken", "chain.crl"] {
            assert_eq!(verify(Some(&dir.join(file)), None, 1).unwrap_err(), format!("cannot load certificate \"{}\": PEM_read_bio_X509_AUX() failed", dir.join(file).display()));
        }
        for file in ["empty", "broken.crl", "root.crt"] {
            assert_eq!(verify(None, Some(&dir.join(file)), 1).unwrap_err(), format!("cannot load CRL \"{}\": PEM_read_bio_X509_CRL() failed", dir.join(file).display()));
        }
        assert!(verify(None, None, 1).unwrap().check(&der(END), &[der(INT)], &name("end")).is_err());
    }

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("twinx-tls-{}", std::process::id()));
        // Written once: the tests run at the same time, and read them.
        static WRITTEN: std::sync::Once = std::sync::Once::new();
        WRITTEN.call_once(|| {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("c.pem"), CERT).unwrap();
            std::fs::write(dir.join("k.pem"), KEY).unwrap();
        });
        dir
    }

    #[test]
    fn loads_certificates() {
        let dir = dir();
        assert_eq!(load(&dir.join("c.pem"), &dir.join("k.pem"), None, false).unwrap().0.len(), 1);
        assert_eq!(load(&dir.join("none"), &dir.join("k.pem"), None, false).unwrap_err(), format!("cannot load certificate \"{}\"", dir.join("none").display()));
        assert_eq!(load(&dir.join("c.pem"), &dir.join("c.pem"), None, false).unwrap_err(), format!("cannot load certificate key \"{}\"", dir.join("c.pem").display()));
        assert!(load(&dir.join("c.pem"), &dir.join("k.pem"), Some(&dir.join("none")), false).unwrap_err().starts_with("open() "));
        assert_eq!(trusted(&dir.join("c.pem")).unwrap().len(), 1);
    }

    const ED_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIABI8p3dtZAQNO9IIpddv0KdrpTZgBtF07GcXXMRAqlr\n-----END PRIVATE KEY-----\n";
    const ED_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBMDCB46ADAgECAhQw6INwvSpRntD3tYuScAjkJthNEDAFBgMrZXAwDTELMAkG
A1UEAwwCZWQwIBcNMjYxMTIyMTE0MTE3WhgPMjEyNjEwMjkxMTQxMTdaMA0xCzAJ
BgNVBAMMAmVkMCowBQYDK2VwAyEAL8XKbEjgrlhEUcjM4UHN6toe66wfOnYQD/ra
ShFX2D6jUzBRMB0GA1UdDgQWBBRx0M5Y4lwOex/ffMorAD1tsQoe8TAfBgNVHSME
GDAWgBRx0M5Y4lwOex/ffMorAD1tsQoe8TAPBgNVHRMBAf8EBTADAQH/MAUGAytl
cANBAI+4pL55PDAZuSVQBnX+wbeY2bLsGvIt8cw+b8Ugbunb6nN+nFiEuOXlpGgT
4q04yOy8aX97GVjXKn4C5xldyA0=
-----END CERTIFICATE-----
";

    #[test]
    fn names_each_client_ca_once() {
        let dir = dir();
        std::fs::write(dir.join("dup.pem"), format!("{CERT}{CERT}")).unwrap();
        let names = ca_names(Some(&dir.join("dup.pem"))).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_ref(), X509Certificate::from_der(&der(CERT)).unwrap().1.subject().as_raw());
        assert!(ca_names(None).unwrap().is_empty());
        assert!(ca_names(Some(&dir.join("none"))).is_err());
    }

    #[test]
    fn staples_the_response_of_a_file_or_fetched() {
        let dir = dir();
        std::fs::write(dir.join("resp.der"), b"response").unwrap();
        let key = certified(vec![der(CERT)], PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap()).unwrap();
        let stapling = |file: Option<&str>, responder: Option<&str>| Stapling { verify: false, responder: responder.map(str::to_string), file: file.map(|f| dir.join(f)) };
        let filed = Staple::new(&key, &stapling(Some("resp.der"), None), &[]).unwrap().unwrap();
        let fixed = Fixed(vec![key.clone()], vec![Some(filed)]);
        assert_eq!(fixed.choose(&[]).unwrap().ocsp.as_deref(), Some(&b"response"[..]));
        assert!(Staple::new(&key, &stapling(Some("none"), None), &[]).unwrap_err().starts_with("BIO_new_file("));
        assert!(Staple::new(&key, &stapling(None, Some("http://127.0.0.1:1/")), &[]).unwrap().is_none());
        let fetched = Arc::new(Staple { source: Some(("http://127.0.0.1:1/".into(), Vec::new(), Vec::new(), Vec::new())), verify: false, state: Mutex::new((None, 0, false)) });
        assert!(fetched.key(&key).ocsp.is_none());
        while fetched.state.lock().unwrap().2 { std::thread::yield_now(); }
        assert!(fetched.state.lock().unwrap().1 > chrono::Utc::now().timestamp());
    }

    #[test]
    fn gives_the_client_certificate_in_pem() {
        let session = Session { cert: Some(der(CERT)), ..Session::default() };
        assert_eq!(session.client_var("raw_cert"), CERT);
        let escaped = session.client_var("escaped_cert");
        assert!(escaped.starts_with("-----BEGIN%20CERTIFICATE-----%0AMIIBfzCCASWgAwIBAgIUL%2Fk6"));
        assert!(escaped.ends_with("wYWN%0A-----END%20CERTIFICATE-----%0A"));
        assert_eq!(pem(b"ab"), "-----BEGIN CERTIFICATE-----\nYWI=\n-----END CERTIFICATE-----\n");
        assert_eq!(Session::default().client_var("raw_cert"), "");
        assert_eq!(session.client_var("cert"), format!("{}\n", CERT.trim_end().replace('\n', "\n\t")));
    }

    #[test]
    fn takes_the_cipher_suites_of_ssl_ciphers() {
        let names = |list: &str| ciphers(list).map(|s| s.iter().map(|s| s.suite().as_str().unwrap_or_default().to_string()).collect::<Vec<_>>());
        assert_eq!(names("DEFAULT:ECCdraft").unwrap().len(), rustls::crypto::ring::DEFAULT_CIPHER_SUITES.len());
        let one = names("ECDHE-RSA-AES128-GCM-SHA256 unknown").unwrap();
        assert_eq!(one.iter().filter(|n| !n.starts_with("TLS13")).collect::<Vec<_>>(), ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]);
        assert!(one.iter().any(|n| n.starts_with("TLS13")));
        assert_eq!(names("ECCdraft").unwrap_err(), "SSL_CTX_set_cipher_list(\"ECCdraft\") failed");
    }

    #[test]
    fn presents_the_certificate_the_client_can_verify() {
        let key = |cert: &str, key: &str| certified(vec![der(cert)], PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap()).unwrap();
        let (ec, ed) = (key(CERT, KEY), key(ED_CERT, ED_KEY));
        let fixed = Fixed::new(vec![ed.clone(), key(CERT, KEY), ec.clone()]);
        assert_eq!(fixed.0.len(), 2);
        assert!(Arc::ptr_eq(&fixed.0[1], &ec));
        let chosen = |schemes: &[SignatureScheme]| fixed.choose(schemes).unwrap();
        assert!(Arc::ptr_eq(&chosen(&[SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519]), &ec));
        assert!(Arc::ptr_eq(&chosen(&[SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ED25519]), &ed));
        assert!(Arc::ptr_eq(&chosen(&[SignatureScheme::RSA_PSS_SHA256]), &ed));
        assert!(Fixed::new(Vec::new()).choose(&[SignatureScheme::ED25519]).is_none());
    }

    #[test]
    fn loads_the_certificate_a_connection_names() {
        let dir = dir();
        let names = [(&*dir.join("$ssl_server_name"), &*dir.join("k.pem"))];
        let files = (&names[..], None);
        let options = Options { verify: false, sessions: Sessions::default(), compress: false, ciphers: None, protocols: [true, true], prefer: false, curves: None, crl: None, depth: 1, ocsp: None, ticket_keys: Vec::new(), stapling: None, client_ca: None };
        let tls = server(files, Some(Some(Arc::new(CertCache::new(4, 60, 10)))), &[], options.clone()).unwrap();
        let addrs = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
        assert!(tls.for_connection(addrs, "c.pem").is_some());
        assert!(tls.for_connection(addrs, "none").is_none());
        assert!(server(files, None, &[], options.clone()).is_err());
        assert!(server(files, Some(Some(Arc::new(CertCache::new(4, 60, 10)))), &[], Options { protocols: [false, false], ..options }).is_ok());
    }

    #[test]
    fn reads_trusted_certificates_without_their_trust_settings() {
        let cert = CertificateDer::pem_slice_iter(CERT.as_bytes()).next().unwrap().unwrap();
        let aux = [0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let trusted = pem(&[cert.as_ref(), &aux].concat()).replace("CERTIFICATE", "TRUSTED CERTIFICATE");
        let certs = certificates(format!("{KEY}{trusted}{CERT}").as_bytes()).unwrap();
        assert_eq!(certs, [cert.clone(), cert]);
        assert_eq!(certificates(b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n"), None);
    }

    #[test]
    fn takes_files_loaded_before_while_their_time_and_inode_stay() {
        let path = dir().join(format!("kept-{}", std::process::id()));
        std::fs::write(&path, "a").unwrap();
        assert_eq!(read(&path, true).unwrap(), b"a");
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, "b").unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(mtime).unwrap();
        new_configuration(true);
        assert_eq!((read(&path, true).unwrap(), read(&path, false).unwrap()), (b"a".to_vec(), b"b".to_vec()));
        new_configuration(false);
        assert_eq!(read(&path, true).unwrap(), b"b");
        std::fs::write(&path, "x").unwrap();
        assert_eq!(read(&path, true).unwrap(), b"b");
        new_configuration(true);
        let new = path.with_extension("new");
        std::fs::write(&new, "c").unwrap();
        std::fs::rename(&new, &path).unwrap();
        assert_eq!(read(&path, true).unwrap(), b"c");
    }

    #[test]
    fn decrypts_keys_with_the_password_that_works() {
        let dir = dir();
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjFTCshcGXqRQICCAAw\nDAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEE4Q9tYczPUHfCtbunvgXjcEgZCF\nZEkeGhOhIcDghmEGcasLrWUT9mM7JCtGch9N9XhIdxCtpRVi7y7BdDoJx3qbbuL/\ns13ZM5I8hD8DXSitMu7hbJGEg332YbZ/h8qknf0owJaNNWwj2t2tiOT4gR6Ei9C4\n6HZM+qGHgPRfZoSlQpEBrlAJmGaXPXcBu3LZ1K5KmJbzaz9kp+jdx9GbkrYbH8g=\n-----END ENCRYPTED PRIVATE KEY-----\n";
        std::fs::write(dir.join("e.pem"), encrypted).unwrap();
        std::fs::write(dir.join("passwords"), "wrong\nright\n").unwrap();
        std::fs::write(dir.join("wrong"), "wrong").unwrap();
        assert!(load(&dir.join("c.pem"), &dir.join("e.pem"), Some(&dir.join("passwords")), false).is_ok());
        assert!(load(&dir.join("c.pem"), &dir.join("e.pem"), Some(&dir.join("wrong")), false).is_err());
    }

    #[test]
    fn verifies_and_names_client_certificates() {
        let cert = CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap();
        assert_eq!(verified(&[], (&[], None, 1), None), "NONE");
        assert_eq!(verified(std::slice::from_ref(&cert), (std::slice::from_ref(&cert), None, 1), None), "SUCCESS");
        assert_eq!(verified(std::slice::from_ref(&cert), (&[], None, 1), None), "FAILED:self-signed certificate");
        assert_eq!(subject(&cert).as_deref(), Some("CN=localhost"));
    }

    #[test]
    fn names_and_takes_curves_as_openssl() {
        assert_eq!((curve(0x0017), curve(0x001d), curve(0x11ec)), ("prime256v1".into(), "X25519".into(), "0x11ec".into()));
        let names = |l: &str| curves(l).map(|g| g.iter().map(|g| curve(u16::from(g.name()))).collect::<Vec<_>>().join(":"));
        assert_eq!(names("prime256v1").unwrap(), "prime256v1");
        assert_eq!(names("x25519:P-384:secp256r1").unwrap(), "X25519:secp384r1:prime256v1");
        assert_eq!(names("auto").unwrap(), "X25519:prime256v1:secp384r1");
        assert_eq!(names("prime256v1:nope").unwrap_err(), "SSL_CTX_set1_curves_list(\"prime256v1:nope\") failed");
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
    fn shared_ticket_keys_rotate_after_the_timeout() {
        let keys = Rotated { rotate: Some(10), file: Vec::new(), keys: Mutex::new(None) };
        let first = keys.encrypt(b"a").unwrap();
        assert_eq!(&keys.encrypt(b"b").unwrap()[..16], &first[..16]);
        keys.keys.lock().unwrap().as_mut().unwrap().0 = now();
        let next = keys.encrypt(b"c").unwrap();
        assert_ne!(&next[..16], &first[..16]);
        assert_eq!((keys.decrypt(&first), keys.decrypt(&next), keys.decrypt(b"x")), (Some(b"a".to_vec()), Some(b"c".to_vec()), None));
        let fixed = Rotated { rotate: None, file: Vec::new(), keys: Mutex::new(None) };
        let first = fixed.encrypt(b"a").unwrap();
        fixed.keys.lock().unwrap().as_mut().unwrap().0 = now() + 1;
        assert_eq!(&fixed.encrypt(b"b").unwrap()[..16], &first[..16]);
    }

    #[test]
    fn ticket_keys_from_files_encrypt_with_the_first() {
        let dir = dir();
        let (short, long, bad) = (dir.join("t48.key"), dir.join("t80.key"), dir.join("t1.key"));
        std::fs::write(&short, [b'1'; 48]).unwrap();
        std::fs::write(&long, [b'2'; 80]).unwrap();
        std::fs::write(&bad, b"1").unwrap();
        let keys = Rotated { rotate: Some(10), file: vec![TicketKey::load(&long).unwrap(), TicketKey::load(&short).unwrap()], keys: Mutex::new(None) };
        let ticket = keys.encrypt(b"a").unwrap();
        assert_eq!((&ticket[..16], keys.decrypt(&ticket)), (&[b'2'; 16][..], Some(b"a".to_vec())));
        let other = Rotated { rotate: None, file: vec![TicketKey::load(&short).unwrap()], keys: Mutex::new(None) };
        let theirs = other.encrypt(b"b").unwrap();
        assert_eq!((keys.decrypt(&theirs), other.decrypt(&ticket)), (Some(b"b".to_vec()), None));
        let mut forged = theirs.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!((keys.decrypt(&forged), keys.decrypt(&theirs[..20])), (None, None));
        assert!(TicketKey::load(&bad).unwrap_err().ends_with("must be 48 or 80 bytes"));
        assert!(TicketKey::load(&dir.join("none")).unwrap_err().starts_with("open() "));
    }

    #[test]
    fn sessions_last_for_the_timeout() {
        let timed = Timed((), 10);
        let stamped = Timed::<()>::stamp(b"data");
        assert_eq!(timed.fresh(stamped.clone()), Some(b"data".to_vec()));
        let old = [(now() - 11).to_be_bytes().as_slice(), b"data"].concat();
        assert_eq!((timed.fresh(old), timed.fresh(b"short".to_vec())), (None, None));
        let tickets = Timed(Rotated { rotate: None, file: Vec::new(), keys: Mutex::new(None) }, 10);
        use rustls::server::ProducesTickets;
        assert!(tickets.enabled() && tickets.lifetime() == 10);
        assert_eq!(tickets.decrypt(&tickets.encrypt(b"t").unwrap()), Some(b"t".to_vec()));
    }

    async fn listener() -> (tokio::net::TcpListener, SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr)
    }

    #[test]
    fn rejects_handshakes_and_lends_the_default_certificate() {
        let dir = dir();
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let text = format!("http {{ server {{ listen {addr} ssl; server_name localhost; ssl_certificate c.pem; ssl_certificate_key k.pem; }} server {{ listen {addr}; server_name virtual1; }} server {{ listen {addr}; server_name virtual2; ssl_reject_handshake on; }} }}");
            let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", text), Path::new("t")).unwrap(), &dir).unwrap());
            let accepted = tokio::task::spawn_local(async move {
                let mut names = Vec::new();
                for _ in 0..2 { names.push(accept(l.accept().await.unwrap().0, &config, addr).await.map(|a| a.1.server_name)); }
                names
            });
            let tls = client((false, true, [true, true]), None, None).unwrap();
            let ok = connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), Some("virtual1")), Duration::from_secs(5), &tls).await.unwrap();
            drop(ok);
            let refused = connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), Some("virtual2")), Duration::from_secs(5), &tls).await.err().unwrap();
            assert!(format!("{refused:?}").contains("UnrecognisedName"), "{refused:?}");
            assert_eq!(accepted.await.unwrap(), [Some("virtual1".to_string()), None]);
        });
    }

    #[test]
    fn passes_data_both_ways_until_closed() {
        use tokio::io::AsyncReadExt;
        let dir = dir();
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; ssl_verify_client optional_no_ca; ssl_trusted_certificate c.pem; }} }}");
            let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", text), Path::new("t")).unwrap(), &dir).unwrap());
            assert_eq!(config.servers[0].ssl, [addr]);
            let accepted = tokio::task::spawn_local(async move { accept(l.accept().await.unwrap().0, &config, addr).await.unwrap() });
            let c = dir.join("c.pem");
            let tls = client((false, true, [true, true]), Some((&c, &dir.join("k.pem"), None)), None).unwrap();
            let mut client = connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), Some("localhost")), Duration::from_secs(5), &tls).await.unwrap();
            let (mut server, session) = accepted.await.unwrap();
            assert!(matches!(server, Stream::Server(_)) && matches!(client, Stream::Client(_)));
            assert_eq!((session.id.len(), session.cipher.as_str(), session.cert.as_ref()), (64, "TLS_AES_256_GCM_SHA384", Some(&der(CERT))));
            assert!(session.ciphers.starts_with("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"), "{}", session.ciphers);
            let session = Session { id: String::new(), cipher: String::new(), ciphers: String::new(), cert: None, ..session };
            assert_eq!(session, Session { protocol: "TLSv1.3".into(), server_name: "localhost".into(), reused: false, verify: "SUCCESS".into(), subject: Some("CN=localhost".into()), curve: "X25519".into(), curves: "X25519:prime256v1:secp384r1".into(), sigalg: "ecdsa_secp256r1_sha256".into(), client_sigalg: "ecdsa_secp256r1_sha256".into(), ..Session::default() });
            let mut buf = [0u8; 4];
            assert!(crate::stream::write_all(&mut client, b"ping", None).await);
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            assert!(crate::stream::write_all(&mut server, b"pong", None).await);
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
            server.shutdown().await.unwrap();
            assert_eq!(client.read(&mut buf).await.unwrap(), 0);
            drop(client);
            assert_eq!(crate::stream::read_into(&mut server, &mut Vec::new(), None).await, 0);
        });
    }

    #[test]
    fn offers_h2_only_where_the_server_speaks_it() {
        let dir = dir();
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let text = format!("http {{ server {{ listen {addr} ssl; server_name localhost; ssl_certificate c.pem; ssl_certificate_key k.pem; http2 on; }} server {{ listen {addr}; server_name plain; }} }}");
            let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", text), Path::new("t")).unwrap(), &dir).unwrap());
            let accepted = tokio::task::spawn_local(async move {
                let mut alpn = Vec::new();
                for _ in 0..2 { alpn.push(accept(l.accept().await.unwrap().0, &config, addr).await.unwrap().1.alpn); }
                alpn
            });
            let mut tls = (*client((false, true, [true, true]), None, None).unwrap()).clone();
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let tls = Arc::new(tls);
            for name in ["localhost", "plain"] {
                drop(connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), Some(name)), Duration::from_secs(5), &tls).await.unwrap());
            }
            assert_eq!(accepted.await.unwrap(), ["h2", "http/1.1"]);
        });
    }

    #[test]
    fn a_client_offers_the_protocols_of_proxy_ssl_protocols() {
        assert!(client((true, false, [false, false]), None, None).is_err());
        let dir = dir();
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let text = format!("http {{ server {{ listen {addr} ssl; server_name localhost; ssl_certificate c.pem; ssl_certificate_key k.pem; ssl_protocols TLSv1.3; }} }}");
            let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", text), Path::new("t")).unwrap(), &dir).unwrap());
            tokio::task::spawn_local(async move { loop { let s = l.accept().await.unwrap().0; drop(accept(s, &config, addr).await) } });
            let connected = |protocols| async move { connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), None), Duration::from_secs(5), &client((true, false, protocols), None, None).unwrap()).await.is_ok() };
            assert!(connected([false, true]).await);
            assert!(connected([true, true]).await);
            assert!(!connected([true, false]).await);
        });
    }

    #[test]
    fn a_client_for_http2_offers_h2_alone() {
        let base = client((true, false, [true, true]), None, None).unwrap();
        assert!(base.alpn_protocols.is_empty());
        assert_eq!(h2(&base).alpn_protocols, [b"h2".to_vec()]);
        let dir = dir();
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let text = format!("http {{ server {{ listen {addr} ssl; server_name localhost; ssl_certificate c.pem; ssl_certificate_key k.pem; http2 on; }} }}");
            let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", text), Path::new("t")).unwrap(), &dir).unwrap());
            let accepted = tokio::task::spawn_local(async move { accept(l.accept().await.unwrap().0, &config, addr).await.unwrap().1.alpn });
            drop(connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), None), Duration::from_secs(5), &h2(&base)).await.unwrap());
            assert_eq!(accepted.await.unwrap(), "h2");
        });
    }

    #[test]
    fn a_handshake_that_does_not_end_in_time_times_out() {
        crate::stream::block_on(async {
            let (_l, addr) = listener().await;
            let e = connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), None), Duration::from_millis(100), &client((true, false, [true, true]), None, None).unwrap()).await.unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        });
    }

    #[test]
    fn a_failed_handshake_gives_no_connection() {
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let peer = tokio::task::spawn_local(async move { let mut s = l.accept().await.unwrap().0; s.write_all(b"HTTP/1.0 400\r\n\r\n").await.unwrap(); });
            assert!(connect(TcpStream::connect(addr).await.unwrap(), (addr.ip(), None), Duration::from_secs(5), &client((true, false, [true, true]), None, None).unwrap()).await.is_err());
            peer.await.unwrap();
            let config = crate::conf::build(&crate::config::parse(&format!("events {{ }} {}", "http { }"), Path::new("t")).unwrap(), &dir()).unwrap();
            let (l, addr) = listener().await;
            let mut other = TcpStream::connect(addr).await.unwrap();
            other.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            assert!(accept(l.accept().await.unwrap().0, &config, addr).await.is_none());
            drop(TcpStream::connect(addr).await.unwrap());
            assert!(accept(l.accept().await.unwrap().0, &config, addr).await.is_none());
        });
    }

    #[test]
    fn tells_plain_connections_by_their_first_byte() {
        crate::stream::block_on(async {
            let (l, addr) = listener().await;
            let mut open = Vec::new();
            for (first, expected) in [(&b"GET"[..], Some(true)), (&[0x16, 3, 1][..], Some(false)), (&[0x80][..], Some(false)), (&[][..], Some(false))] {
                let mut other = TcpStream::connect(addr).await.unwrap();
                other.write_all(first).await.unwrap();
                if first.is_empty() { drop(other) } else { open.push(other) }
                assert_eq!(plain(&l.accept().await.unwrap().0).await, expected);
            }
        });
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
        assert_eq!((fetch(true, &a, false), fetch(false, &b, false), fetch(false, &a, false)), (2, 3, 4));
        assert_eq!(fetch(false, &a, true), 5);
        cache.nodes.lock().unwrap().last_mut().unwrap().created = 0;
        assert_eq!(fetch(false, &a, false), 5);
        (cache.nodes.lock().unwrap().last_mut().unwrap().created, cache.nodes.lock().unwrap().last_mut().unwrap().file) = (0, (0, 0));
        assert_eq!(fetch(false, &a, false), 6);
        for _ in 0..2 { cache.fetch(false, &none, false, &uncached).unwrap(); }
        assert_eq!(loads.get(), 8);
        assert!(cache.fetch(false, &a, true, &|| Err("failed".into())).is_err());
        assert_eq!(cache.nodes.lock().unwrap().len(), 1);
        cache.nodes.lock().unwrap()[0].accessed = 0;
        fetch(true, &b, false);
        assert_eq!(cache.nodes.lock().unwrap().len(), 1);
    }

    #[test]
    fn loads_the_certificate_for_a_connection() {
        let dir = dir();
        std::fs::write(dir.join("other.pem"), "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwQWPnC2Jx/3u3hdA\njGUmqcD72PuhGmag3j4c7dVV64OhRANCAATANLzVnsMiRvhgpGBwTwrnsEsESgL3\nwQJBCIlLunPAFCk9taxLVaqjkHBX5E7184ZLnPSc8ZVLhpB/saEm9hMD\n-----END PRIVATE KEY-----\n").unwrap();
        let (base, cache) = (client((true, false, [true, true]), None, None).unwrap(), CertCache::new(4, 60, 10));
        let (cert, key, other) = (dir.join("c.pem"), dir.join("k.pem"), dir.join("other.pem"));
        assert!(client_cert(&base, (&cert, &key, None), Some(&cache)).is_ok());
        assert!(client_cert(&base, (&cert, &key, None), None).is_ok());
        assert!(client_cert(&base, (&cert, &other, None), Some(&cache)).unwrap_err().starts_with("SSL_use_PrivateKey("));
        assert!(client_cert(&base, (&dir.join("none"), &key, None), None).is_err());
    }
}
