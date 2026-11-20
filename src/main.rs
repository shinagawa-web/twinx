//! twinx: an HTTP server that reads nginx's configuration and behaves as nginx does.

mod conf;
mod expires;
mod config;
mod http;
mod log;
mod resolver;
mod upstream;
mod vars;

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libc::{SIGCHLD, SIGINT, SIGQUIT, SIGTERM, c_int, pid_t, sigset_t};

/// What `-V` prints: Test::Nginx reads it to tell which modules twinx has.
const CONFIGURE: &str = "--without-http_fastcgi_module --without-http_uwsgi_module \
--with-http_gunzip_module --with-http_gzip_static_module --without-http_scgi_module --without-http_grpc_module --without-http_memcached_module";

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

/// The signals the master and its worker wait for. They are blocked, and taken with `sigwait`.
fn signal_set() -> sigset_t {
    // SAFETY: the set is initialised by sigemptyset before it is used.
    unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [SIGQUIT, SIGTERM, SIGINT, SIGCHLD] { libc::sigaddset(&mut set, s); }
        set
    }
}

fn wait_signal(set: &sigset_t) -> c_int {
    let mut sig = 0;
    // SAFETY: set is a valid signal set and sig a valid place for the result.
    unsafe { libc::sigwait(set, &mut sig) };
    sig
}

/// Runs as nginx does with `master_process on`: the master opens the sockets, writes the pid file and
/// handles the signals; a worker process serves the requests. A worker that ends is started again.
fn run(a: &Args) -> Result<(), String> {
    let config = Arc::new(load(a)?);
    let listeners = http::bind(&config)?;
    let set = signal_set();
    // SAFETY: the master is single-threaded here; blocking signals has no other effect on it.
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    let pid = &config.pid;
    std::fs::write(pid, format!("{}\n", std::process::id())).map_err(|e| format!("open() \"{}\" failed ({e})", pid.display()))?;
    let mut worker = spawn(&config, &listeners, &set)?;
    loop {
        let sig = wait_signal(&set);
        if sig != SIGCHLD {
            // SAFETY: plain system calls on the worker's process id.
            unsafe { libc::kill(worker, sig); libc::waitpid(worker, std::ptr::null_mut(), 0) };
            break;
        }
        // SAFETY: reaps any ended child without blocking.
        while let ended @ 1.. = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } {
            if ended == worker { worker = spawn(&config, &listeners, &set)?; }
        }
    }
    let _ = std::fs::remove_file(pid);
    Ok(())
}

/// Starts a worker process. It serves until it gets QUIT, TERM or INT, then exits.
fn spawn(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<pid_t, String> {
    // SAFETY: the master has no other threads, so the child starts in a consistent state.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork() failed ({})", std::io::Error::last_os_error())),
        0 => {
            if let Err(e) = http::accept(config.clone(), listeners) { fail(&e, None) }
            while wait_signal(set) == SIGCHLD {}
            std::process::exit(0)
        }
        child => Ok(child),
    }
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

    #[test]
    fn takes_blocked_signals() {
        let set = signal_set();
        assert!([SIGQUIT, SIGTERM, SIGINT, SIGCHLD].iter().all(|&s| unsafe { libc::sigismember(&set, s) } == 1));
        // Blocked in this thread only, and raised for this thread, so other tests do not see it.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()); libc::raise(SIGCHLD) };
        assert_eq!(wait_signal(&set), SIGCHLD);
    }
}
