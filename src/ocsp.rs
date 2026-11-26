use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use x509_parser::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Ocsp {
    pub leaf: bool,
    pub responder: Option<String>,
    pub cache: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    Good,
    Revoked,
    Unknown,
}

struct Entry {
    len: usize,
    key: [u8; 128],
    status: u8,
    valid: i64,
    stored: u64,
}

struct Head {
    lock: AtomicBool,
    stored: AtomicU64,
}

#[derive(Clone, Copy)]
struct Zone {
    head: &'static Head,
    entries: *mut Entry,
    n: usize,
}

// SAFETY: the entries are only touched while the lock in head is held.
unsafe impl Send for Zone {}

static ZONES: Mutex<Vec<(String, u64, Zone)>> = Mutex::new(Vec::new());

/// Made while the master reads the configuration, so that the workers it forks next share it.
pub fn zone(name: &str, size: u64) -> Result<(), String> {
    let mut zones = ZONES.lock().unwrap();
    if zones.iter().any(|z| z.0 == name && z.1 == size) { return Ok(()) }
    let head = crate::shm::shared(Head { lock: AtomicBool::new(false), stored: AtomicU64::new(0) })?;
    let n = usize::try_from(size).unwrap_or(usize::MAX) / size_of::<Entry>();
    let entries = crate::shm::zeroed(n * size_of::<Entry>())?.cast::<Entry>();
    zones.retain(|z| z.0 != name);
    zones.push((name.to_string(), size, Zone { head, entries, n }));
    Ok(())
}

impl Zone {
    fn find(name: &str) -> Option<Zone> {
        ZONES.lock().unwrap().iter().find(|z| z.0 == name).map(|z| z.2)
    }

    fn locked<R>(&self, f: impl FnOnce(&mut [Entry]) -> R) -> R {
        while self.head.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { std::thread::yield_now() }
        // SAFETY: zeroed memory is a table of empty entries, and the lock gives this thread the only access to it.
        let r = f(unsafe { std::slice::from_raw_parts_mut(self.entries, self.n) });
        self.head.lock.store(false, Ordering::Release);
        r
    }

    fn lookup(&self, key: &[u8], now: i64) -> Option<Status> {
        self.locked(|entries| {
            let e = entries.iter_mut().find(|e| e.len > 0 && &e.key[..e.len] == key)?;
            if e.valid > now { return Some([Status::Good, Status::Revoked, Status::Unknown][usize::from(e.status)]) }
            e.len = 0;
            None
        })
    }

    fn store(&self, key: &[u8], status: Status, valid: i64, now: i64) {
        if valid < now || key.len() > 128 { return }
        let stored = self.head.stored.fetch_add(1, Ordering::Relaxed) + 1;
        self.locked(|entries| {
            let same = entries.iter().position(|e| e.len > 0 && &e.key[..e.len] == key);
            let Some(at) = same.or_else(|| entries.iter().position(|e| e.len == 0)).or_else(|| (0..entries.len()).min_by_key(|&i| entries[i].stored)) else { return };
            let mut e = Entry { len: key.len(), key: [0; 128], status: status as u8, valid, stored };
            e.key[..key.len()].copy_from_slice(key);
            entries[at] = e;
        })
    }
}

const TIMEOUT: Duration = Duration::from_secs(60);

impl Ocsp {
    pub fn check(&self, chain: &[X509Certificate]) -> Result<(), &'static str> {
        let n = if self.leaf { chain.len().min(2) } else { chain.len() };
        for pair in chain[..n].windows(2) {
            match self.status(&pair[0], &pair[1]).ok_or("certificate status request failed")? { Status::Good => {} Status::Revoked => return Err("certificate revoked"), Status::Unknown => return Err("certificate status unknown") }
        }
        Ok(())
    }

    fn status(&self, cert: &X509Certificate, issuer: &X509Certificate) -> Option<Status> {
        let (id, now) = (cert_id(cert, issuer), chrono::Utc::now().timestamp());
        let zone = self.cache.as_deref().and_then(Zone::find);
        if let Some(status) = zone.and_then(|z| z.lookup(&id, now)) { return Some(status) }
        let url = self.responder.clone().or_else(|| responder(cert))?;
        let (status, next) = verify(&fetch(&url, &request(&id))?, &id, issuer, now, true)?;
        if let Some(z) = zone { z.store(&id, status, next.unwrap_or(now + 3600), now) }
        Some(status)
    }
}

pub fn request(id: &[u8]) -> Vec<u8> {
    der(0x30, &der(0x30, &der(0x30, &der(0x30, id))))
}

pub fn stapled(chain: &[rustls::pki_types::CertificateDer], trusted: &[rustls::pki_types::CertificateDer], responder_url: Option<&str>) -> Option<(String, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let cert = X509Certificate::from_der(chain.first()?).ok()?.1;
    let issued = |d: &&rustls::pki_types::CertificateDer| X509Certificate::from_der(d).is_ok_and(|(_, c)| c.subject().as_raw() == cert.issuer().as_raw() && cert.verify_signature(Some(c.public_key())).is_ok());
    let issuer_der = chain[1..].iter().chain(trusted).find(issued)?;
    let id = cert_id(&cert, &X509Certificate::from_der(issuer_der).ok()?.1);
    Some((responder_url.map(str::to_string).or_else(|| responder(&cert))?, request(&id), id, issuer_der.to_vec()))
}

pub fn staple(url: &str, (request, id, issuer): (&[u8], &[u8], &[u8]), check: bool, now: i64) -> Option<(Vec<u8>, Option<i64>)> {
    let body = fetch(url, request)?;
    let (status, next) = verify(&body, id, &X509Certificate::from_der(issuer).ok()?.1, now, check)?;
    (status == Status::Good).then_some((body, next))
}

fn sha1(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref().to_vec()
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len().to_be_bytes();
    let len: Vec<u8> = if content.len() < 128 { vec![content.len() as u8] } else { let l: Vec<u8> = len.into_iter().skip_while(|b| *b == 0).collect(); [vec![0x80 | l.len() as u8], l].concat() };
    [&[tag][..], &len, content].concat()
}

fn tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
    let (&tag, rest) = d.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let n = if first < 0x80 { 0 } else { usize::from(first & 0x7f) };
    let len = if first < 0x80 { usize::from(first) } else { rest.get(..n).filter(|_| n <= 4)?.iter().fold(0, |l, b| l << 8 | usize::from(*b)) };
    let content = rest.get(n..n + len)?;
    Some((tag, content, &d[..2 + n + len], &rest[n + len..]))
}

fn items(mut d: &[u8]) -> Option<Vec<(u8, &[u8], &[u8])>> {
    let mut out = Vec::new();
    while let Some((tag, content, whole, rest)) = tlv(d).filter(|_| !d.is_empty()) { out.push((tag, content, whole)); d = rest; }
    d.is_empty().then_some(out)
}

fn cert_id(cert: &X509Certificate, issuer: &X509Certificate) -> Vec<u8> {
    const SHA1: &[u8] = &[0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00];
    let key = sha1(&issuer.public_key().subject_public_key.data);
    der(0x30, &[SHA1, &der(0x04, &sha1(cert.issuer().as_raw())), &der(0x04, &key), &der(0x02, cert.raw_serial())].concat())
}

fn responder(cert: &X509Certificate) -> Option<String> {
    let ocsp = |d: &AccessDescription| match &d.access_location { GeneralName::URI(u) if d.access_method == oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP => Some(u.to_string()), _ => None };
    cert.extensions().iter().find_map(|e| match e.parsed_extension() { ParsedExtension::AuthorityInfoAccess(a) => a.accessdescs.iter().find_map(ocsp), _ => None })
}

fn fetch(url: &str, request: &[u8]) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let addr = host.parse::<SocketAddr>().ok().or_else(|| host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 80)))?;
    let slash = if path.ends_with('/') { "" } else { "/" };
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT).ok()?;
    s.set_read_timeout(Some(TIMEOUT)).ok()?;
    s.write_all(format!("GET {path}{slash}{} HTTP/1.0\r\nHost: {host}\r\n\r\n", crate::tls::escape(&crate::tls::base64(request))).as_bytes()).ok()?;
    let mut answer = Vec::new();
    s.read_to_end(&mut answer).ok()?;
    let mut lines = Vec::new();
    let mut at = 0;
    while let Some(n) = answer[at..].iter().position(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(&answer[at..at + n]).trim_end_matches('\r').to_string();
        at += n + 1;
        if line.is_empty() { break }
        lines.push(line);
    }
    let ok = lines.first()?.split(' ').nth(1) == Some("200");
    let typed = lines.iter().any(|l| l.split_once(':').is_some_and(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.trim().eq_ignore_ascii_case("application/ocsp-response")));
    (ok && typed).then(|| answer[at..].to_vec())
}

fn verify(body: &[u8], id: &[u8], issuer: &X509Certificate, now: i64, check: bool) -> Option<(Status, Option<i64>)> {
    const BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
    let response = items(tlv(body)?.1)?;
    let bytes = items(tlv(response.get(1)?.1)?.1)?;
    if response[0].1 != [0] || bytes.first()?.1 != BASIC { return None }
    let basic = items(tlv(bytes.get(1)?.1)?.1)?;
    let (tbs, alg, sig) = (basic.first()?, basic.get(1)?, basic.get(2)?);
    let sent = basic.get(3).and_then(|c| items(tlv(c.1)?.1)).unwrap_or_default();
    let certs: Vec<X509Certificate> = sent.iter().filter_map(|c| X509Certificate::from_der(c.2).ok().map(|c| c.1)).collect();
    let data: Vec<_> = items(tbs.1)?.into_iter().filter(|e| e.0 != 0xa0).collect();
    let (id_of, responses) = (data.first()?, items(data.get(2)?.1)?);
    let names = |c: &&X509Certificate| match id_of.0 { 0xa1 => c.subject().as_raw() == id_of.1, _ => tlv(id_of.1).is_some_and(|k| k.1 == sha1(&c.public_key().subject_public_key.data)) };
    let signer = certs.iter().chain([issuer]).find(names)?;
    let (alg, bits) = (AlgorithmIdentifier::from_der(alg.2).ok()?.1, sig.1.split_first()?);
    x509_parser::verify::verify_signature(signer.public_key(), &alg, &x509_parser::asn1_rs::BitString::new(*bits.0, bits.1), tbs.2).ok()?;
    let itself = signer.subject().as_raw() == issuer.subject().as_raw() && signer.public_key().raw == issuer.public_key().raw;
    let delegated = signer.issuer().as_raw() == issuer.subject().as_raw() && signer.verify_signature(Some(issuer.public_key())).is_ok() && signer.extended_key_usage().ok().flatten().is_some_and(|e| e.value.ocsp_signing);
    let single = responses.iter().filter_map(|r| items(r.1)).find(|r| r.first().is_some_and(|c| c.2 == id)).filter(|_| !check || itself || delegated)?;
    let status = match single.get(1)?.0 { 0x80 => Status::Good, 0xa1 => Status::Revoked, _ => Status::Unknown };
    let time = |d: &[u8]| chrono::NaiveDateTime::parse_from_str(std::str::from_utf8(d).ok()?, "%Y%m%d%H%M%SZ").ok().map(|t| t.and_utc().timestamp());
    let this = time(single.get(2)?.1)?;
    let next = match single.get(3).filter(|e| e.0 == 0xa0) { Some(e) => Some(time(tlv(e.1)?.1)?), None => None };
    (this <= now + 300 && next.is_none_or(|n| n >= now - 300)).then_some((status, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    #[test]
    fn reads_and_writes_der() {
        assert_eq!(der(0x04, b"ab"), b"\x04\x02ab");
        let long = der(0x04, &[7; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);
        let (tag, content, whole, rest) = tlv(&[&long[..], b"\x05\x00"].concat()).map(|(t, c, w, r)| (t, c.to_vec(), w.to_vec(), r.to_vec())).unwrap();
        assert_eq!((tag, content, whole, rest), (0x04, vec![7; 200], long.clone(), b"\x05\x00".to_vec()));
        assert_eq!(items(b"\x02\x01\x05\x05\x00").unwrap(), vec![(0x02, &[5][..], &[2, 1, 5][..]), (0x05, &[][..], &[5, 0][..])]);
        assert!(items(b"\x02\x05\x01").is_none());
        assert!(tlv(b"\x02\x85\x01\x01\x01\x01\x01").is_none());
    }

    #[test]
    fn checks_nothing_of_a_lone_certificate_and_fails_without_a_responder() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ocsp.pem")).unwrap();
        let ders: Vec<Vec<u8>> = rustls::pki_types::CertificateDer::pem_slice_iter(text.as_bytes()).map(|c| c.unwrap().to_vec()).collect();
        let certs: Vec<X509Certificate> = ders.iter().map(|d| X509Certificate::from_der(d).unwrap().1).collect();
        let ocsp = Ocsp { leaf: true, responder: None, cache: None };
        assert_eq!(ocsp.check(&certs[1..]), Ok(()));
        assert_eq!(responder(&certs[0]).as_deref(), Some("http://127.0.0.1:1"));
        assert_eq!(ocsp.check(&certs), Err("certificate status request failed"));
        let id = cert_id(&certs[0], &certs[1]);
        assert_eq!(&id[..13], &[0x30, id.len() as u8 - 2, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]);
        assert!(verify(b"\x30\x03\x0a\x01\x01", &id, &certs[1], 0, true).is_none());
        assert!(fetch("https://127.0.0.1/", b"").is_none());
    }

    #[test]
    fn finds_what_stapling_asks() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ocsp.pem")).unwrap();
        let ders: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(text.as_bytes()).map(|c| c.unwrap()).collect();
        let certs: Vec<X509Certificate> = ders.iter().map(|d| X509Certificate::from_der(d).unwrap().1).collect();
        let id = cert_id(&certs[0], &certs[1]);
        assert_eq!(stapled(&ders, &[], None), Some(("http://127.0.0.1:1".to_string(), request(&id), id.clone(), ders[1].to_vec())));
        assert_eq!(stapled(&ders[..1], &ders[1..], Some("http://127.0.0.1:2/")).unwrap().0, "http://127.0.0.1:2/");
        assert!(stapled(&ders[..1], &[], None).is_none());
        assert!(staple("http://127.0.0.1:1", (&request(&id), &id, &ders[1]), true, 0).is_none());
    }
}
