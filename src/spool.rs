use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const PIECE: u64 = 2 * 32768;

pub fn temp_path(dir: &Path, levels: &[usize]) -> PathBuf {
    numbered(dir, levels, crate::shm::temp_number(1) as u32)
}

fn numbered(dir: &Path, levels: &[usize], n: u32) -> PathBuf {
    let name = format!("{n:010}");
    let mut end = name.len();
    let mut path = dir.to_path_buf();
    for &l in levels { path.push(&name[end - l..end]); end -= l; }
    path.join(name)
}

pub fn failed(call: &str, path: &Path, e: &Error) -> String {
    let text = e.to_string();
    format!("{call} \"{}\" failed ({}: {})", path.display(), e.raw_os_error().unwrap_or(0), text.split(" (os error").next().unwrap_or_default())
}

pub fn make_dirs(dirs: &[PathBuf], owner: Option<u32>) -> Result<(), String> {
    for dir in dirs {
        match DirBuilder::new().mode(0o700).create(dir) {
            Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(failed("mkdir()", dir, &e)),
            _ => {}
        }
        let Some(uid) = owner else { continue };
        if let Err(e) = std::os::unix::fs::chown(dir, Some(uid), None) {
            let text = e.to_string();
            return Err(format!("chown(\"{}\", {uid}) failed ({}: {})", dir.display(), e.raw_os_error().unwrap_or(0), text.split(" (os error").next().unwrap_or_default()));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Spool<'a> { dir: &'a Path, levels: &'a [usize], max: u64, pub at_once: usize, file: Option<(File, PathBuf)>, written: u64, read: u64, seen: u64 }

impl<'a> Spool<'a> {
    pub fn new((dir, levels): (&'a Path, &'a [usize]), max: usize, at_once: usize) -> Spool<'a> {
        Spool { dir, levels, max: max as u64, at_once, file: None, written: 0, read: 0, seen: 0 }
    }

    pub fn room(&self) -> u64 {
        self.max.saturating_sub(self.written)
    }

    pub fn left(&self) -> u64 {
        self.written - self.read
    }

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

    pub fn read(&mut self, to: &mut Vec<u8>) -> Result<(), String> {
        let Some((file, path)) = &self.file else { return Ok(()) };
        to.resize(PIECE.min(self.left()) as usize, 0);
        file.read_exact_at(to, self.read).map_err(|e| failed("pread()", path, &e))?;
        self.read += to.len() as u64;
        self.seen = self.written;
        Ok(())
    }

    pub fn drop_unseen(&mut self) {
        self.written = self.seen.max(self.read);
    }
}

fn create(dir: &Path, levels: &[usize]) -> Result<(File, PathBuf), String> {
    let (file, path) = open_new(dir, levels)?;
    let _ = std::fs::remove_file(&path);
    Ok((file, path))
}

pub fn open_new(dir: &Path, levels: &[usize]) -> Result<(File, PathBuf), String> {
    let mut path = temp_path(dir, levels);
    loop {
        match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => return Ok((file, path)),
            // Taken by another worker or left behind: skip ahead rather than try each next number.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                crate::shm::temp_number(std::process::id().into());
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
    fn makes_directories_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir("dirs");
        let dirs = [dir.clone(), dir.join("a")];
        make_dirs(&dirs, None).unwrap();
        assert!(dirs.iter().all(|d| d.metadata().unwrap().permissions().mode() & 0o777 == 0o700));
        std::fs::write(dir.join("b"), "").unwrap();
        make_dirs(&[dir.join("a"), dir.join("b")], None).unwrap();
        let missing = dir.join("c/d");
        assert_eq!(make_dirs(&[missing.clone()], None), Err(format!("mkdir() \"{}\" failed (2: No such file or directory)", missing.display())));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_what_is_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir("keeps");
        let mut s = Spool::new((&dir, &[1, 2]), 100_000, 8192);
        assert_eq!((s.room(), s.left()), (100_000, 0));
        let path = s.write(&[b'a'; 40_000], 10).unwrap().unwrap().to_path_buf();
        assert!(path.starts_with(&dir) && path.parent().unwrap().exists() && !path.exists(), "{path:?}");
        assert_eq!(s.file.as_ref().unwrap().0.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(s.write(&[b'b'; 40_000], 10).unwrap(), None);
        let mut piece = Vec::new();
        s.read(&mut piece).unwrap();
        assert!(piece.len() == 65_536 && piece[..40_000] == [b'a'; 40_000] && piece[40_000..] == [b'b'; 25_536]);
        assert_eq!((s.left(), s.room()), (14_464, 20_000));
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
        let next = crate::shm::last_temp_number() as u32 + 1;
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
