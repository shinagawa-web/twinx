//! twinx: an HTTP server that reads nginx's configuration and behaves as nginx does.

mod conf;
mod config;
mod http;
mod vars;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;

/// What `-V` prints: Test::Nginx reads it to tell which modules twinx has.
const CONFIGURE: &str = "--without-http_fastcgi_module --without-http_uwsgi_module \
--without-http_scgi_module --without-http_grpc_module --without-http_memcached_module";

/// The command line, as nginx takes it.
#[derive(Debug, PartialEq)]
struct Args {
    prefix: PathBuf,
    conf: PathBuf,
    error_log: PathBuf,
    globals: String,
    version: bool,
}

fn args(list: &[String]) -> Result<Args, String> {
    let mut values = [("-p", "/usr/local/twinx/"), ("-c", "conf/nginx.conf"), ("-e", "logs/error.log"), ("-g", "")].map(|(o, v)| (o, v.to_string()));
    let mut version = false;
    let mut it = list.iter();
    while let Some(arg) = it.next() {
        if arg == "-V" || arg == "-v" { version = true; continue; }
        let slot = values.iter_mut().find(|(o, _)| o == arg).ok_or_else(|| format!("invalid option: \"{arg}\""))?;
        slot.1 = it.next().cloned().ok_or_else(|| format!("option \"{arg}\" requires an argument"))?;
    }
    let [p, c, e, g] = values.map(|(_, v)| v);
    Ok(Args { prefix: p.into(), conf: c.into(), error_log: e.into(), globals: g, version })
}

/// Reads the configuration: the -g directives first, then the file.
fn load(a: &Args) -> Result<conf::Config, String> {
    let file = a.prefix.join(&a.conf);
    let text = std::fs::read_to_string(&file).map_err(|e| format!("open() \"{}\" failed ({e})", file.display()))?;
    let mut main = config::parse(&a.globals, Path::new("command line"))?;
    main.extend(config::parse(&text, &file)?);
    conf::build(&main, &a.prefix)
}

fn run(a: &Args) -> Result<(), String> {
    let mut signals = Signals::new([SIGQUIT, SIGTERM, SIGINT]).map_err(|e| e.to_string())?;
    let config = Arc::new(load(a)?);
    http::listen(config.clone())?;
    let pid = &config.pid;
    std::fs::write(pid, format!("{}\n", std::process::id())).map_err(|e| format!("open() \"{}\" failed ({e})", pid.display()))?;
    signals.forever().next();
    let _ = std::fs::remove_file(pid);
    Ok(())
}

fn main() {
    let list: Vec<String> = std::env::args().skip(1).collect();
    let a = args(&list).unwrap_or_else(|e| fail(&e, None));
    if a.version {
        eprintln!("twinx version: {}\nconfigure arguments: {CONFIGURE}", http::NAME);
        return;
    }
    if let Err(e) = run(&a) { fail(&e, Some(&a.prefix.join(&a.error_log))) }
}

/// Reports an error as nginx does, on standard error and in the error log, and exits.
fn fail(msg: &str, log: Option<&Path>) -> ! {
    eprintln!("twinx: [emerg] {msg}");
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let line = format!("{time} [emerg] {}#0: {msg}\n", std::process::id());
    let file = log.and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
    let _ = file.map(|mut f| f.write_all(line.as_bytes()));
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn command_line() {
        let a = args(&strings(&["-p", "/t/", "-c", "nginx.conf", "-e", "error.log", "-g", "pid x;"])).unwrap();
        assert_eq!((a.prefix.to_str(), a.conf.to_str(), a.globals.as_str()), (Some("/t/"), Some("nginx.conf"), "pid x;"));
        assert!(args(&strings(&["-V"])).unwrap().version);
        assert_eq!(args(&strings(&["-x"])).unwrap_err(), "invalid option: \"-x\"");
        assert_eq!(args(&strings(&["-p"])).unwrap_err(), "option \"-p\" requires an argument");
    }
}
