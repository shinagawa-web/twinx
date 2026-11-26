use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Word(String),
    Semi,
    Open,
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub block: Option<Vec<Directive>>,
    pub at: String,
}

pub fn tokenize(text: &str) -> Result<Vec<(Tok, usize)>, (String, usize)> {
    let b = text.as_bytes();
    let (mut out, mut i, mut line) = (Vec::new(), 0, 1);
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => line += 1,
            b' ' | b'\t' | b'\r' => {}
            b';' => out.push((Tok::Semi, line)),
            b'{' => out.push((Tok::Open, line)),
            b'}' => out.push((Tok::Close, line)),
            b'#' => i = text[i..].find('\n').map_or(b.len(), |n| i + n) - 1,
            b'"' | b'\'' => {
                let (start, mut raw) = (line, Vec::new());
                i += 1;
                while i < b.len() && b[i] != c {
                    if b[i] == b'\\' && i + 1 < b.len() { raw.push(b[i]); i += 1; }
                    line += (b[i] == b'\n') as usize;
                    raw.push(b[i]);
                    i += 1;
                }
                if i >= b.len() { return Err(("unexpected end of file, expecting \";\" or \"}\"".into(), line)); }
                let next = b.get(i + 1).copied().unwrap_or(b' ');
                // ")" may follow, as a word of its own (the end of a condition of if).
                if !b" \t\r\n;{})".contains(&next) { return Err((format!("unexpected \"{}\"", next as char), line)); }
                out.push((Tok::Word(unescape(&raw)), start));
            }
            _ => {
                let (start, mut raw, mut var) = (i, Vec::new(), false);
                while i < b.len() && !b" \t\r\n;".contains(&b[i]) {
                    let opens = b[i] == b'{' && i > start && b[i - 1] == b'$';
                    if !var && !opens && b"{}".contains(&b[i]) { break; }
                    if b[i] == b'\\' && i + 1 < b.len() { raw.push(b[i]); i += 1; }
                    var = (var && b[i] != b'}') || opens;
                    raw.push(b[i]);
                    i += 1;
                }
                out.push((Tok::Word(unescape(&raw)), line));
                continue;
            }
        }
        i += 1;
    }
    Ok(out)
}

fn unescape(raw: &[u8]) -> String {
    let (mut out, mut i) = (Vec::with_capacity(raw.len()), 0);
    while i < raw.len() {
        let escaped = raw[i] == b'\\' && matches!(raw.get(i + 1), Some(b'"' | b'\'' | b'\\' | b't' | b'r' | b'n'));
        i += escaped as usize;
        out.push(if escaped { match raw[i] { b't' => b'\t', b'r' => b'\r', b'n' => b'\n', c => c } } else { raw[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse(text: &str, file: &Path) -> Result<Vec<Directive>, String> {
    parse_in(text, file, file.parent().unwrap_or(Path::new("")))
}

pub fn parse_in(text: &str, file: &Path, dir: &Path) -> Result<Vec<Directive>, String> {
    let at = |line: usize| format!("{}:{}", file.display(), line);
    let toks = tokenize(text).map_err(|(msg, line)| format!("{msg} in {}", at(line)))?;
    let mut stack: Vec<Vec<Directive>> = vec![Vec::new()];
    let mut words: Vec<(String, usize)> = Vec::new();
    for (tok, line) in toks {
        match tok {
            Tok::Word(w) => words.push((w, line)),
            Tok::Semi | Tok::Open => {
                let c = if tok == Tok::Semi { ';' } else { '{' };
                if words.is_empty() { return Err(format!("unexpected \"{c}\" in {}", at(line))); }
                let first = words.remove(0);
                if first.0 == "include" {
                    if tok == Tok::Open { return Err(format!("directive \"include\" is not terminated by \";\" in {}", at(first.1))); }
                    if words.len() != 1 { return Err(format!("invalid number of arguments in \"include\" directive in {}", at(first.1))); }
                    let included = include(&words.pop().unwrap().0, dir, &at(first.1))?;
                    stack.last_mut().unwrap().extend(included);
                    continue;
                }
                let d = Directive {
                    name: first.0,
                    args: words.drain(..).map(|w| w.0).collect(),
                    block: (tok == Tok::Open).then(Vec::new),
                    at: at(first.1),
                };
                stack.last_mut().unwrap().push(d);
                if tok == Tok::Open { stack.push(Vec::new()); }
            }
            Tok::Close => {
                if stack.len() == 1 || !words.is_empty() { return Err(format!("unexpected \"}}\" in {}", at(line))); }
                let inner = stack.pop().unwrap();
                stack.last_mut().unwrap().last_mut().unwrap().block = Some(inner);
            }
        }
    }
    let line = text.lines().count().max(1);
    if !words.is_empty() || stack.len() > 1 { return Err(format!("unexpected end of file, expecting \";\" or \"}}\" in {}", at(line))); }
    Ok(stack.pop().unwrap())
}

fn include(name: &str, dir: &Path, at: &str) -> Result<Vec<Directive>, String> {
    let path = dir.join(name);
    let files = if path.to_string_lossy().contains(['*', '?', '[']) { glob(&path).ok_or_else(|| format!("glob() \"{}\" failed in {at}", path.display()))? } else { vec![path] };
    let mut out = Vec::new();
    for file in files {
        // Kept open while its own includes are read, so that a loop of includes ends when descriptors run out.
        let mut f = File::open(&file).map_err(|e| format!("{} in {at}", crate::spool::failed("open()", &file, &e)))?;
        let mut text = String::new();
        f.read_to_string(&mut text).map_err(|e| format!("{} in {at}", crate::spool::failed("read()", &file, &e)))?;
        out.extend(parse_in(&text, &file, dir)?);
    }
    Ok(out)
}

fn glob(pattern: &Path) -> Option<Vec<PathBuf>> {
    let c = CString::new(pattern.as_os_str().as_bytes()).ok()?;
    // SAFETY: glob fills the zeroed glob_t; its paths are copied out before globfree releases them.
    unsafe {
        let mut g: libc::glob_t = std::mem::zeroed();
        let n = libc::glob(c.as_ptr(), 0, None, &mut g);
        let paths = (0..g.gl_pathc).map(|i| PathBuf::from(OsStr::from_bytes(CStr::from_ptr(*g.gl_pathv.add(i)).to_bytes()))).collect();
        libc::globfree(&mut g);
        (n == 0 || n == libc::GLOB_NOMATCH).then_some(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Result<Vec<Directive>, String> {
        parse(text, Path::new("t.conf"))
    }

    #[test]
    fn nested_blocks_and_args() {
        let d = p("http { server { listen 80; } }\n").unwrap();
        assert_eq!(d[0].name, "http");
        let server = &d[0].block.as_ref().unwrap()[0];
        let listen = &server.block.as_ref().unwrap()[0];
        assert_eq!((listen.name.as_str(), listen.args.clone()), ("listen", vec!["80".to_string()]));
        assert_eq!(listen.at, "t.conf:1");
    }

    #[test]
    fn quotes_escapes_comments_and_variables() {
        let d = p("a 'x y' \"q\\\"\" b\\;c ${v} t\\tn\\n{ # c\n}\nf $u;").unwrap();
        assert_eq!(d[0].args, vec!["x y", "q\"", "b\\;c", "${v}", "t\tn\n"]);
        assert_eq!(d[1].at, "t.conf:3");
    }

    #[test]
    fn errors() {
        assert_eq!(p("a;\n}").unwrap_err(), "unexpected \"}\" in t.conf:2");
        assert_eq!(p("a {").unwrap_err(), "unexpected end of file, expecting \";\" or \"}\" in t.conf:1");
        assert_eq!(p(";").unwrap_err(), "unexpected \";\" in t.conf:1");
        assert_eq!(p("a \"b\"c;").unwrap_err(), "unexpected \"c\" in t.conf:1");
        assert_eq!(p("if ($a = \"b\") { }").unwrap()[0].args, ["($a", "=", "b", ")"]);
    }
}
