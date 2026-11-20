//! Upstream groups and nginx's weighted round-robin balancing, with
//! max_fails and fail_timeout, and backup servers tried after the others.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub addr: SocketAddr,
    pub weight: i64,
    pub max_fails: u64,
    pub fail_timeout: u64,
    pub backup: bool,
}

impl Peer {
    /// A server with nginx's defaults: weight=1 max_fails=1 fail_timeout=10s.
    pub fn new(addr: SocketAddr) -> Peer {
        Peer { addr, weight: 1, max_fails: 1, fail_timeout: 10, backup: false }
    }
}

#[derive(Debug, Default, Clone)]
struct State {
    current: i64,
    effective: i64,
    fails: u64,
    accessed: u64,
    checked: u64,
}

#[derive(Debug)]
pub struct Upstream {
    pub peers: Vec<Peer>,
    state: Mutex<Vec<State>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Upstream {
    pub fn new(peers: Vec<Peer>) -> Upstream {
        let state = peers.iter().map(|p| State { effective: p.weight, ..State::default() }).collect();
        Upstream { peers, state: Mutex::new(state) }
    }

    /// The next server to try, given those already tried for this request:
    /// the primary servers first, then the backup ones, as
    /// ngx_http_upstream_get_peer() chooses them.
    pub fn pick(&self, tried: &mut [bool]) -> Option<usize> {
        let mut state = self.state.lock().unwrap();
        let single = self.peers.len() == 1;
        let now = now();
        [false, true].into_iter().find_map(|backup| {
            let (mut best, mut total): (Option<(usize, i64)>, i64) = (None, 0);
            for (i, p) in self.peers.iter().enumerate().filter(|(i, p)| p.backup == backup && !tried[*i]) {
                let s = &mut state[i];
                if !single && p.max_fails > 0 && s.fails >= p.max_fails && now - s.checked <= p.fail_timeout { continue; }
                s.current += s.effective;
                total += s.effective;
                s.effective += (s.effective < p.weight) as i64;
                if best.is_none_or(|(_, current)| s.current > current) { best = Some((i, s.current)); }
            }
            let (b, _) = best?;
            state[b].current -= total;
            if now - state[b].checked > self.peers[b].fail_timeout { state[b].checked = now; }
            tried[b] = true;
            Some(b)
        })
    }

    /// Records how a server answered, as ngx_http_upstream_free_round_robin_peer() does.
    pub fn done(&self, i: usize, failed: bool) {
        let mut state = self.state.lock().unwrap();
        let (p, s) = (&self.peers[i], &mut state[i]);
        if !failed {
            if s.accessed < s.checked { s.fails = 0; }
            return;
        }
        let now = now();
        (s.fails, s.accessed, s.checked) = (s.fails + 1, now, now);
        if p.max_fails > 0 { s.effective = (s.effective - p.weight / p.max_fails as i64).max(0); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers(n: usize, max_fails: u64) -> Upstream {
        let peers = (0..n).map(|i| Peer { max_fails, ..Peer::new(SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16))) });
        Upstream::new(peers.collect())
    }

    #[test]
    fn round_robin() {
        let u = peers(2, 1);
        let picks: Vec<usize> = (0..4).map(|_| u.pick(&mut [false, false]).unwrap()).collect();
        assert_eq!(picks, vec![0, 1, 0, 1]);
    }

    #[test]
    fn failed_servers_rest_and_backups_come_last() {
        let mut u = peers(2, 1);
        u.peers[1].backup = true;
        let u = Upstream::new(u.peers.clone());
        let mut tried = [false, false];
        assert_eq!(u.pick(&mut tried), Some(0));
        u.done(0, true);
        assert_eq!(u.pick(&mut tried), Some(1));
        assert_eq!(u.pick(&mut tried), None);
        assert_eq!(u.pick(&mut [false, false]), Some(1));
        u.done(1, false);
    }
}
