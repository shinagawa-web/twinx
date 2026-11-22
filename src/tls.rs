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

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, Connection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme};

use crate::conf::Config;

/// How long a client has to finish its handshake, as client_header_timeout's default.
const HANDSHAKE: Duration = Duration::from_secs(60);

/// The certificate chain and the private key of ssl_certificate and ssl_certificate_key, in PEM.
pub fn certificate(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>, String> {
    let chain = CertificateDer::pem_file_iter(cert).and_then(|certs| certs.collect::<Result<Vec<_>, _>>()).ok().filter(|c| !c.is_empty());
    let chain = chain.ok_or_else(|| format!("cannot load certificate \"{}\"", cert.display()))?;
    let signing = PrivateKeyDer::from_pem_file(key).ok().and_then(|k| provider().key_provider.load_private_key(k).ok());
    let signing = signing.ok_or_else(|| format!("cannot load certificate key \"{}\"", key.display()))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
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

/// What a listening address with "ssl" accepts connections with.
pub fn server(config: Arc<Config>, listen: SocketAddr) -> Arc<ServerConfig> {
    Arc::new(ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(Sni(config, listen))))
}

/// Takes a TLS connection from a client: the handshake, then the plain end of it.
pub fn accept(tcp: TcpStream, config: &Arc<ServerConfig>) -> Option<TcpStream> {
    let conn = ServerConnection::new(config.clone()).ok()?;
    pipe(tcp, conn.into(), HANDSHAKE)
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

/// Connects to a proxied server over TLS without SNI, as proxy_ssl_server_name
/// off does; the plain end of the connection, None when the handshake fails.
pub fn connect(tcp: TcpStream, peer: IpAddr, timeout: Duration) -> Option<TcpStream> {
    static CLIENT: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let config = CLIENT.get_or_init(|| {
        let verifier = Arc::new(Unverified(provider().signature_verification_algorithms));
        let mut c = ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
        c.enable_sni = false;
        Arc::new(c)
    });
    let conn = ClientConnection::new(config.clone(), ServerName::from(peer)).ok()?;
    pipe(tcp, conn.into(), timeout)
}

/// Completes the handshake, then passes data between the TLS connection and
/// one end of a socket pair in a thread of its own, and gives the other end,
/// on which twinx reads and writes as on a TCP connection.
fn pipe(mut tcp: TcpStream, mut tls: Connection, timeout: Duration) -> Option<TcpStream> {
    let _ = tcp.set_read_timeout(Some(timeout));
    while tls.is_handshaking() { tls.complete_io(&mut tcp).ok()?; }
    let _ = tcp.set_read_timeout(None);
    let (ours, theirs) = UnixStream::pair().ok()?;
    std::thread::spawn(move || pump(tcp, tls, theirs));
    // SAFETY: the descriptor is a connected stream socket that nothing else owns; the
    // calls twinx makes on a TcpStream (read, write, shutdown, timeouts, poll) work on it.
    Some(unsafe { TcpStream::from_raw_fd(ours.into_raw_fd()) })
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
        assert_eq!(certificate(&dir.join("c.pem"), &dir.join("k.pem")).unwrap().cert.len(), 1);
        assert_eq!(certificate(&dir.join("none"), &dir.join("k.pem")).unwrap_err(), format!("cannot load certificate \"{}\"", dir.join("none").display()));
        assert_eq!(certificate(&dir.join("c.pem"), &dir.join("c.pem")).unwrap_err(), format!("cannot load certificate key \"{}\"", dir.join("c.pem").display()));
    }

    #[test]
    fn passes_data_both_ways_until_closed() {
        let dir = dir();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr} ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, Path::new("t")).unwrap(), &dir).unwrap());
        assert_eq!(config.servers[0].ssl, [addr]);
        let tls = server(config, addr);
        let accepted = std::thread::spawn(move || accept(l.accept().unwrap().0, &tls).unwrap());
        let mut client = connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5)).unwrap();
        let mut server = accepted.join().unwrap();
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
    fn a_failed_handshake_gives_no_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let peer = std::thread::spawn(move || { let mut s = l.accept().unwrap().0; s.write_all(b"HTTP/1.0 400\r\n\r\n").unwrap(); });
        assert!(connect(TcpStream::connect(addr).unwrap(), addr.ip(), Duration::from_secs(5)).is_none());
        peer.join().unwrap();
    }
}
