use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::conf::Level;
use crate::vars::{Escape, Request, Sent, Template};

#[derive(Debug)]
pub struct Format {
    pub line: Template,
    pub escape: Escape,
}

#[derive(Debug)]
pub enum Target {
    File(Arc<File>),
    Path(Template),
}

#[derive(Debug)]
pub struct AccessLog {
    pub target: Target,
    pub format: Arc<Format>,
    pub condition: Option<Template>,
    pub gzip: Option<u32>,
}

impl AccessLog {
    pub fn write(&self, level: &Level, r: &Request, s: &Sent) {
        let skip = self.condition.as_ref().map(|c| c.render(r, s)).is_some_and(|c| c.is_empty() || c == "0");
        if skip { return; }
        let mut line = self.format.line.log_line(r, s, self.format.escape);
        line.push(b'\n');
        if let Some(level) = self.gzip {
            let mut gz = GzEncoder::new(Vec::new(), Compression::new(level));
            line = gz.write_all(&line).and_then(|_| gz.finish()).unwrap_or_default();
        }
        match &self.target {
            Target::File(file) => drop((&**file).write_all(&line)),
            // As nginx does, nothing is written when the root directory of the request does not exist.
            Target::Path(_) if !level.alias.as_deref().unwrap_or(&level.root).is_dir() => {}
            Target::Path(path) => {
                let path = PathBuf::from(path.render(r, s));
                match &level.log_cache {
                    Some(cache) => cache.write(&path, &line),
                    None => drop(open(&path).and_then(|mut f| f.write_all(&line))),
                }
            }
        }
    }
}

fn open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[derive(Debug)]
pub struct Cache {
    pub max: usize,
    pub inactive: Duration,
    pub min_uses: u32,
    pub valid: Duration,
    entries: Mutex<Vec<Entry>>,
}

#[derive(Debug)]
struct Entry {
    path: PathBuf,
    file: Option<File>,
    uses: u32,
    opened: Instant,
    used: Instant,
}

impl Cache {
    pub fn new(max: usize, inactive: Duration, min_uses: u32, valid: Duration) -> Cache {
        Cache { max, inactive, min_uses, valid, entries: Mutex::new(Vec::new()) }
    }

    fn write(&self, path: &Path, data: &[u8]) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|e| now - e.used <= self.inactive);
        let found = entries.iter().position(|e| e.path == path).map(|i| entries.remove(i));
        let new = found.is_none();
        let mut e = found.unwrap_or(Entry { path: path.to_path_buf(), file: None, uses: 0, opened: now, used: now });
        if e.file.is_none() || now - e.opened >= self.valid { (e.file, e.opened) = (open(path).ok(), now); }
        let Some(file) = &mut e.file else { return };
        let _ = file.write_all(data);
        (e.uses, e.used) = (e.uses + 1, now);
        if e.uses < self.min_uses { e.file = None; }
        if new && entries.len() >= self.max { entries.pop(); }
        entries.insert(0, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keeps_descriptors_of_paths_used_often() {
        let dir = std::env::temp_dir().join(format!("twinx-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Cache::new(2, Duration::from_secs(20), 2, Duration::from_secs(60));
        for name in ["a", "a", "b", "c"] { cache.write(&dir.join(name), b"x\n"); }
        let kept: Vec<_> = cache.entries.lock().unwrap().iter().map(|e| (e.path.clone(), e.file.is_some())).collect();
        assert_eq!(kept, vec![(dir.join("c"), false), (dir.join("b"), false)]);
        cache.write(&dir.join("c"), b"x\n");
        std::fs::remove_file(dir.join("c")).unwrap();
        cache.write(&dir.join("c"), b"y\n");
        cache.write(&dir.join("missing/d"), b"y\n");
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), b"x\nx\n");
    }
}
