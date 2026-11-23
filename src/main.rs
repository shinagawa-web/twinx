//! twinx: an HTTP server that reads nginx's configuration and behaves as nginx does.

mod conf;
mod expires;
mod config;
mod http;
mod log;
mod ocsp;
mod resolver;
mod stream;
mod tls;
mod upstream;
mod vars;

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, c_int, pid_t, sigset_t};

/// What `-V` prints: Test::Nginx reads it to tell which modules twinx has.
const CONFIGURE: &str = "--with-http_ssl_module --without-http_fastcgi_module --without-http_uwsgi_module \
--with-http_gunzip_module --with-http_gzip_static_module --without-http_scgi_module --without-http_grpc_module --without-http_memcached_module";

/// The TLS library line of `-V`. twinx does TLS with rustls; nginx-tests reads
/// "with OpenSSL <version>" to tell which TLS features there are, so it names
/// the version of the reference nginx, whose features twinx takes after.
/// Servers are selected by the name clients send with SNI, as nginx says it does.
const TLS_LIBRARY: &str = "built with TLS by rustls, compatible with OpenSSL 3.5.7\nTLS SNI support enabled";

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
        for s in [SIGQUIT, SIGTERM, SIGINT, SIGHUP] { libc::sigaddset(&mut set, s); }
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
/// handles the signals; a worker process serves the requests, so a signal sent to the worker alone
/// ends only the worker, and the master and its pid file stay.
fn run(a: &Args) -> Result<(), String> {
    let config = Arc::new(load(a)?);
    let mut listeners = http::bind(&config, &[])?;
    let set = signal_set();
    // SAFETY: the master is single-threaded here; blocking signals has no other effect on it.
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    let pid = &config.pid;
    std::fs::write(pid, format!("{}\n", std::process::id())).map_err(|e| format!("open() \"{}\" failed ({e})", pid.display()))?;
    let mut worker = spawn(&config, &listeners, &set)?;
    // HUP reloads the configuration: a worker starts with the new one, on the sockets it shares with the
    // old configuration, and the old worker is shut down. A configuration that cannot be loaded leaves the
    // old worker serving, as in nginx.
    let sig = loop {
        let sig = wait_signal(&set);
        if sig != SIGHUP { break sig }
        let Ok((config, open)) = load(a).map(Arc::new).and_then(|c| Ok((c.clone(), http::bind(&c, &listeners)?))).map_err(|e| emerg(&e, Some(&a.prefix.join(&a.error_log)))) else { continue };
        let old = std::mem::replace(&mut worker, spawn(&config, &open, &set)?);
        listeners = open;
        let mut status = 0;
        // SAFETY: plain system calls on the old worker's process id: shut it down and wait for it.
        unsafe { libc::kill(old, SIGQUIT); libc::waitpid(old, &mut status, 0) };
        log(&config.notice_logs, "notice", &format!("worker process {old} exited with code {}", libc::WEXITSTATUS(status)));
    };
    // SAFETY: plain system calls on the worker's process id: pass the signal on and wait for the worker.
    unsafe { libc::kill(worker, sig); libc::waitpid(worker, std::ptr::null_mut(), 0) };
    let _ = std::fs::remove_file(pid);
    Ok(())
}

/// Starts a worker process. It serves until it gets QUIT, TERM or INT, then exits.
fn spawn(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<pid_t, String> {
    // SAFETY: the master has no other threads, so the child starts in a consistent state.
    let child = unsafe { libc::fork() };
    forked(child, config, listeners, set)
}

/// Goes on in both processes after fork(). It is a function of its own, not inlined, so that each
/// process counts what it runs here in its own coverage profile.
#[inline(never)]
fn forked(child: pid_t, config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<pid_t, String> {
    if child == 0 { worker(config, listeners, set) }
    (child > 0).then_some(child).ok_or_else(|| format!("fork() failed ({})", std::io::Error::last_os_error()))
}

fn worker(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> ! {
    // worker_rlimit_nofile: as in nginx, a failure leaves the limit as it was.
    let limit = config.rlimit_nofile.map(|n| libc::rlimit { rlim_cur: n, rlim_max: n });
    // SAFETY: setrlimit() only reads the structure it is given.
    if let Some(l) = limit { unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &l) }; }
    // working_directory: as in nginx 1.30, a worker that cannot change to it logs an alert and exits
    // with the fatal code 2, and the master does not start it again.
    if let Some((dir, Err(e))) = config.working_directory.as_ref().map(|d| (d, std::env::set_current_dir(d))) {
        let reason = e.to_string().split(" (os error").next().unwrap_or_default().to_string();
        alert(config, &format!("chdir(\"{}\") failed ({}: {reason})", dir.display(), e.raw_os_error().unwrap_or(0)));
        std::process::exit(2)
    }
    // The worker's event loop, on this one thread: it is made after fork(), as
    // the master has to stay single-threaded to fork.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap_or_else(|e| fail(&e.to_string(), None));
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let accepting = http::accept(config.clone(), listeners).unwrap_or_else(|e| fail(&e, None));
        let signals = signal_fd(set).unwrap_or_else(|e| fail(&format!("signalfd() failed ({e})"), None));
        // A worker ignores HUP, which only the master acts on. QUIT shuts it down
        // gracefully; TERM and INT end it at once.
        let mut sig = SIGHUP;
        while sig == SIGHUP { sig = next_signal(&signals).await }
        if sig == SIGQUIT { http::shut_down(accepting, config.shutdown_timeout).await }
    });
    std::process::exit(0)
}

/// A signalfd for the signals of the set, which stay blocked: the event loop
/// reads them from it as they come.
fn signal_fd(set: &sigset_t) -> std::io::Result<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>> {
    use std::os::fd::FromRawFd;
    // SAFETY: set is a valid signal set; the descriptor returned is owned by nothing else.
    let fd = unsafe { libc::signalfd(-1, set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()) }
    // SAFETY: fd is a new descriptor of this process, which the AsyncFd owns and closes.
    unsafe { tokio::io::unix::AsyncFd::register_with_interest(std::os::fd::OwnedFd::from_raw_fd(fd), tokio::io::Interest::READABLE) }.map_err(|e| e.into_parts().1)
}

/// The next signal of a signalfd; TERM when it cannot be read.
async fn next_signal(fd: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>) -> c_int {
    use std::os::fd::AsRawFd;
    loop {
        let Ok(mut ready) = fd.readable().await else { return SIGTERM };
        // SAFETY: an all-zero signalfd_siginfo is valid, and the read writes at most its size into it.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = unsafe { libc::read(fd.as_raw_fd(), (&mut info as *mut libc::signalfd_siginfo).cast(), size_of::<libc::signalfd_siginfo>()) };
        if n == size_of::<libc::signalfd_siginfo>() as isize { return info.ssi_signo as c_int }
        ready.clear_ready();
    }
}

fn main() {
    let list: Vec<String> = std::env::args().skip(1).collect();
    let a = args(&list).unwrap_or_else(|e| fail(&e, None));
    if a.version {
        eprintln!("twinx version: {}\n{TLS_LIBRARY}\nconfigure arguments: {CONFIGURE}", http::NAME);
        return;
    }
    if let Err(e) = run(&a) { fail(&e, Some(&a.prefix.join(&a.error_log))) }
}

/// Reports an error as nginx does, on standard error and in the error log, and exits.
fn fail(msg: &str, log: Option<&Path>) -> ! {
    emerg(msg, log);
    std::process::exit(1)
}

/// Writes an alert to the error logs of the main block.
fn alert(config: &conf::Config, msg: &str) {
    log(&config.alert_logs, "alert", msg)
}

/// Writes a message of a level to error logs.
fn log(logs: &[Arc<std::fs::File>], level: &str, msg: &str) {
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let line = format!("{time} [{level}] {}#0: {msg}\n", std::process::id());
    logs.iter().for_each(|f| { let _ = (&**f).write_all(line.as_bytes()); });
}

/// Reports an error on standard error and in the error log.
fn emerg(msg: &str, log: Option<&Path>) {
    eprintln!("twinx: [emerg] {msg}");
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let line = format!("{time} [emerg] {}#0: {msg}\n", std::process::id());
    let file = log.and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
    let _ = file.map(|mut f| f.write_all(line.as_bytes()));
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
    fn alert_goes_to_the_main_error_logs() {
        let dir = std::env::temp_dir().join(format!("twinx-alert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = config::parse("error_log a.log; error_log b.log emerg;", Path::new("t.conf")).unwrap();
        alert(&conf::build(&main, &dir).unwrap(), "chdir(\"wd\") failed");
        let a = std::fs::read_to_string(dir.join("a.log")).unwrap();
        assert!(a.ends_with(&format!(" [alert] {}#0: chdir(\"wd\") failed\n", std::process::id())));
        assert_eq!(std::fs::read_to_string(dir.join("b.log")).unwrap(), "");
    }

    #[test]
    fn takes_blocked_signals() {
        let set = signal_set();
        assert!([SIGQUIT, SIGTERM, SIGINT].iter().all(|&s| unsafe { libc::sigismember(&set, s) } == 1));
        // Blocked in this thread only, and raised for this thread, so other tests do not see it.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()); libc::raise(SIGINT) };
        assert_eq!(wait_signal(&set), SIGINT);
    }

    #[test]
    fn reads_blocked_signals_on_the_event_loop() {
        let set = signal_set();
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
        stream::block_on(async {
            let fd = signal_fd(&set).unwrap();
            unsafe { libc::raise(SIGHUP) };
            assert_eq!(next_signal(&fd).await, SIGHUP);
            // Nothing else is pending until the next one comes.
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50), next_signal(&fd)).await.is_err());
            unsafe { libc::raise(SIGQUIT) };
            assert_eq!(next_signal(&fd).await, SIGQUIT);
        });
    }
}
