//! TLS: connections accepted on "listen ... ssl" and connections to proxied
//! servers with "proxy_pass https://". The rest of twinx reads and writes plain
//! HTTP; a thread of each TLS connection passes the decrypted bytes through a
//! Unix socket pair, whose other end twinx uses as it uses a TCP connection.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, ClientConnection, Connection, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

use crate::conf::Config;

/// How long a client has to finish its handshake, as client_header_timeout's default.
const HANDSHAKE: Duration = Duration::from_secs(60);

/// A certificate chain and its private key, in PEM. An encrypted key (PKCS #8)
/// is decrypted with the first of the passwords that works, as
/// ssl_password_file has them, one on each line.
fn load(cert: &Path, key: &Path, passwords: Option<&Path>) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain = CertificateDer::pem_file_iter(cert).and_then(|certs| certs.collect::<Result<Vec<_>, _>>()).ok().filter(|c| !c.is_empty());
    let chain = chain.ok_or_else(|| format!("cannot load certificate \"{}\"", cert.display()))?;
    let text = std::fs::read_to_string(key).unwrap_or_default();
    let passwords = passwords.map(|p| std::fs::read_to_string(p).map_err(|e| format!("open() \"{}\" failed ({e})", p.display()))).transpose()?.unwrap_or_default();
    let encrypted = pkcs8::der::Document::from_pem(&text).ok().filter(|(label, _)| *label == "ENCRYPTED PRIVATE KEY").map(|(_, doc)| doc);
    let decrypt = |doc: &pkcs8::der::Document| passwords.lines().find_map(|p| pkcs8::EncryptedPrivateKeyInfoRef::try_from(doc.as_bytes()).ok()?.decrypt(p).ok());
    let found = match encrypted { Some(doc) => decrypt(&doc).map(|d| PrivateKeyDer::Pkcs8(d.as_bytes().to_vec().into())), None => PrivateKeyDer::from_pem_slice(text.as_bytes()).ok() };
    let found = found.filter(|k| provider().key_provider.load_private_key(k.clone_key()).is_ok());
    Ok((chain, found.ok_or_else(|| format!("cannot load certificate key \"{}\"", key.display()))?))
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

/// The files of ssl_certificate, ssl_certificate_key and ssl_password_file;
/// whether clients are asked for a certificate (ssl_verify_client not off),
/// and the files of the certificates theirs are verified with.
pub fn server(cert: &Path, key: &Path, passwords: Option<&Path>, verify: bool, trust: &[&Path]) -> Result<ServerTls, String> {
    let (chain, key) = load(cert, key, passwords)?;
    let trusted = trust.iter().map(|p| trusted(p)).collect::<Result<Vec<_>, _>>()?.concat();
    let builder = ServerConfig::builder();
    let builder = if verify { builder.with_client_cert_verifier(Arc::new(AnyClient(provider().signature_verification_algorithms))) } else { builder.with_no_client_auth() };
    let config = Arc::new(builder.with_single_cert(chain, key).map_err(|e| format!("cannot load certificate \"{}\" ({e})", cert.display()))?);
    Ok(ServerTls { config, trusted })
}

/// What the variables tell of a TLS connection: the protocol ($ssl_protocol,
/// "TLSv1.3"), whether its session was reused ($ssl_session_reused), how the
/// client's certificate was verified ($ssl_client_verify: NONE, SUCCESS or
/// FAILED:reason) and its subject ($ssl_client_s_dn).
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub protocol: String,
    pub reused: bool,
    pub verify: String,
    pub subject: Option<String>,
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
    let tls = crate::http::server(config, listen, hello.client_hello().server_name()).0.tls.as_ref()?;
    let conn = hello.into_connection(tls.config.clone()).ok()?;
    let (stream, mut session, chain) = pipe(tcp, conn.into(), HANDSHAKE).ok()?;
    (session.verify, session.subject) = (verified(&chain, &tls.trusted), chain.first().and_then(|c| subject(c)));
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
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let registry = x509_parser::objects::oid_registry();
    let attr = |a: &x509_parser::x509::AttributeTypeAndValue| format!("{}={}", x509_parser::objects::oid2abbrev(a.attr_type(), registry).map_or_else(|_| a.attr_type().to_id_string(), str::to_string), a.as_str().unwrap_or_default());
    let rdns: Vec<String> = cert.subject().iter_rdn().map(|rdn| rdn.iter().map(attr).collect::<Vec<_>>().join("+")).collect();
    Some(rdns.into_iter().rev().collect::<Vec<_>>().join(","))
}

/// A proxied server's certificate is not verified, as with proxy_ssl_verify
/// off; the handshake's signatures are.
#[derive(Debug)]
struct Unverified(WebPkiSupportedAlgorithms);

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

/// What connections to proxied servers are made with: without SNI, as
/// proxy_ssl_server_name off does; reusing the sessions of earlier
/// connections when proxy_ssl_session_reuse is on; with the certificate of
/// proxy_ssl_certificate, proxy_ssl_certificate_key and proxy_ssl_password_file, if any.
pub fn client(reuse: bool, cert: Option<(&Path, &Path, Option<&Path>)>) -> Result<Arc<ClientConfig>, String> {
    let verifier = Arc::new(Unverified(provider().signature_verification_algorithms));
    let builder = ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier);
    let mut c = match cert.map(|(c, k, p)| load(c, k, p)).transpose()? {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };
    c.enable_sni = false;
    if !reuse { c.resumption = rustls::client::Resumption::disabled(); }
    Ok(Arc::new(c))
}

/// Connects to a proxied server over TLS; the plain end of the connection,
/// or the error the handshake failed with (WouldBlock once the timeout passed).
pub fn connect(tcp: TcpStream, peer: IpAddr, timeout: Duration, config: &Arc<ClientConfig>) -> std::io::Result<TcpStream> {
    let conn = ClientConnection::new(config.clone(), ServerName::from(peer)).map_err(std::io::Error::other)?;
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
    let session = Session { protocol, reused: tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed), verify: String::new(), subject: None };
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
    fn passes_data_both_ways_until_closed() {
        let dir = dir();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; ssl_verify_client optional_no_ca; ssl_trusted_certificate c.pem; }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, Path::new("t")).unwrap(), &dir).unwrap());
        assert_eq!(config.servers[0].ssl, [addr]);
        let accepted = std::thread::spawn(move || accept(l.accept().unwrap().0, &config, addr).unwrap());
        let c = dir.join("c.pem");
        let mut client = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5), &client(false, Some((&c, &dir.join("k.pem"), None))).unwrap()).unwrap();
        let (mut server, session) = accepted.join().unwrap();
        assert_eq!(session, Session { protocol: "TLSv1.3".into(), reused: false, verify: "SUCCESS".into(), subject: Some("CN=localhost".into()) });
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
        let e = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_millis(100), &client(true, None).unwrap()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        drop(l);
    }

    #[test]
    fn a_failed_handshake_gives_no_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let peer = std::thread::spawn(move || { let mut s = l.accept().unwrap().0; s.write_all(b"HTTP/1.0 400\r\n\r\n").unwrap(); });
        assert!(connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5), &client(true, None).unwrap()).is_err());
        peer.join().unwrap();
    }
}
