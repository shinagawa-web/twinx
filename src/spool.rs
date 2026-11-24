//! The files what has come of proxied answers is kept in while their clients are behind.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// How much of a file is read at once: the buffers of output_buffers.
const PIECE: u64 = 2 * 32768;

/// The number of the next temporary file.
static NEXT: AtomicU32 = AtomicU32::new(1);

/// A path for a new temporary file: its number in ten digits, in the subdirectories
/// the levels name, each taken from the end of the name (levels 1 2: 2/00/0000000002).
pub fn temp_path(dir: &Path, levels: &[usize]) -> PathBuf {
    numbered(dir, levels, NEXT.fetch_add(1, Ordering::Relaxed))
}

fn numbered(dir: &Path, levels: &[usize], n: u32) -> PathBuf {
    let name = format!("{n:010}");
    let mut end = name.len();
    let mut path = dir.to_path_buf();
    for &l in levels { path.push(&name[end - l..end]); end -= l; }
    path.join(name)
}

/// What nginx says of a call that failed.
fn failed(call: &str, path: &Path, e: &Error) -> String {
    let text = e.to_string();
    format!("{call} \"{}\" failed ({}: {})", path.display(), e.raw_os_error().unwrap_or(0), text.split(" (os error").next().unwrap_or_default())
}

/// The file of one answer: where files are made, how large it may be, all that was ever
/// written counting, and how much is written at once; how much was written to it and
/// read from it, and how much there was of it when it was last read.
#[derive(Debug)]
pub struct Spool<'a> { dir: &'a Path, levels: &'a [usize], max: u64, pub at_once: usize, file: Option<(File, PathBuf)>, written: u64, read: u64, seen: u64 }

impl<'a> Spool<'a> {
    pub fn new((dir, levels): (&'a Path, &'a [usize]), max: usize, at_once: usize) -> Spool<'a> {
        Spool { dir, levels, max: max as u64, at_once, file: None, written: 0, read: 0, seen: 0 }
    }

    /// How much more may be written.
    pub fn room(&self) -> u64 {
        self.max.saturating_sub(self.written)
    }

    /// How much is to be read.
    pub fn left(&self) -> u64 {
        self.written - self.read
    }

    /// Writes data of so many buffers to the end of the file, which is made first if there is
    /// none: then its path is given.
    pub fn write(&mut self, data: &[u8], buffers: usize) -> Result<Option<&Path>, String> {
        let made = self.file.is_none();
        let (file, path) = match &mut self.file {
            Some(file) => file,
            none => none.insert(create(self.dir, self.levels)?),
        };
        file.write_all_at(data, self.written).map_err(|e| failed(if buffers > 1 { "pwritev()" } else { "pwrite()" }, path, &e))?;
        self.written += data.len() as u64;
        Ok(made.then_some(path))
    }

    /// Reads the next piece.
    pub fn read(&mut self, to: &mut Vec<u8>) -> Result<(), String> {
        let Some((file, path)) = &self.file else { return Ok(()) };
        to.resize(PIECE.min(self.left()) as usize, 0);
        file.read_exact_at(to, self.read).map_err(|e| failed("pread()", path, &e))?;
        self.read += to.len() as u64;
        self.seen = self.written;
        Ok(())
    }

    /// What there was not yet when it was last read will not be.
    pub fn drop_unseen(&mut self) {
        self.written = self.seen.max(self.read);
    }
}

/// A new file, which has no name any more, as ngx_create_temp_file() makes it, with the
/// directories it takes.
fn create(dir: &Path, levels: &[usize]) -> Result<(File, PathBuf), String> {
    let mut path = temp_path(dir, levels);
    loop {
        match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => {
                let _ = std::fs::remove_file(&path);
                return Ok((file, path))
            }
            // One another worker made, or that was left there: not all of those are tried.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                NEXT.fetch_add(std::process::id(), Ordering::Relaxed);
                path = temp_path(dir, levels);
            }
            Err(e) => {
                let parent = path.parent().filter(|p| e.kind() == ErrorKind::NotFound && !p.exists()).ok_or_else(|| failed("open()", &path, &e))?;
                DirBuilder::new().recursive(true).mode(0o700).create(parent).map_err(|e| failed("mkdir()", parent, &e))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("twinx-spool-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn temp_files_under_levels() {
        assert_eq!(numbered(Path::new("/t"), &[], 2), PathBuf::from("/t/0000000002"));
        assert_eq!(numbered(Path::new("/t"), &[1, 2], 2), PathBuf::from("/t/2/00/0000000002"));
        assert_eq!(numbered(Path::new("/t"), &[2, 1, 3], 1234567890), PathBuf::from("/t/90/8/567/1234567890"));
    }

    #[test]
    fn keeps_what_is_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir("keeps");
        let mut s = Spool::new((&dir, &[1, 2]), 100_000, 8192);
        assert_eq!((s.room(), s.left()), (100_000, 0));
        let path = s.write(&[b'a'; 40_000], 10).unwrap().unwrap().to_path_buf();
        // It is made with its directories, and has no name.
        assert!(path.starts_with(&dir) && path.parent().unwrap().exists() && !path.exists(), "{path:?}");
        assert_eq!(s.file.as_ref().unwrap().0.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(s.write(&[b'b'; 40_000], 10).unwrap(), None);
        // It is read in pieces, in order, and all that was written counts.
        let mut piece = Vec::new();
        s.read(&mut piece).unwrap();
        assert!(piece.len() == 65_536 && piece[..40_000] == [b'a'; 40_000] && piece[40_000..] == [b'b'; 25_536]);
        assert_eq!((s.left(), s.room()), (14_464, 20_000));
        // What was written since is dropped, what was there before is not.
        s.write(&[b'c'; 20_000], 5).unwrap();
        assert_eq!((s.left(), s.room()), (34_464, 0));
        s.drop_unseen();
        s.read(&mut piece).unwrap();
        assert!(piece == [b'b'; 14_464] && s.left() == 0);
        s.drop_unseen();
        assert_eq!(s.left(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn files_that_cannot_be_made() {
        let dir = dir("made");
        std::fs::write(&dir, "").unwrap();
        for levels in [&[][..], &[1]] {
            let e = Spool::new((&dir, levels), 100, 100).write(b"x", 1).unwrap_err();
            assert!(e.starts_with(&format!("open() \"{}/", dir.display())) && e.ends_with("\" failed (20: Not a directory)"), "{e}");
        }
        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn files_that_are_there_are_left() {
        let dir = dir("left");
        std::fs::create_dir_all(&dir).unwrap();
        let next = NEXT.load(Ordering::Relaxed);
        for n in next..next + 100 { std::fs::write(dir.join(format!("{n:010}")), "x").unwrap(); }
        let mut s = Spool::new((&dir, &[]), 100, 100);
        s.write(b"abc", 1).unwrap();
        let mut piece = Vec::new();
        s.read(&mut piece).unwrap();
        assert_eq!(piece, b"abc");
        for f in std::fs::read_dir(&dir).unwrap() { assert_eq!(std::fs::read(f.unwrap().path()).unwrap(), b"x"); }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
