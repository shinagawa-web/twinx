mod body;
mod cache;
mod clock;
mod coding;
mod conf;
mod expires;
mod config;
mod h2;
mod http;
mod log;
mod ocsp;
mod resolver;
mod shm;
mod spool;
mod stream;
mod tls;
mod upstream;
mod vars;

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libc::{SIGCHLD, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, c_int, pid_t, sigset_t};

const CONFIGURE: &str = "--with-http_ssl_module --with-http_v2_module --without-http_fastcgi_module --without-http_uwsgi_module \
--with-http_gunzip_module --with-http_gzip_static_module --without-http_scgi_module --without-http_grpc_module --without-http_memcached_module";

/// nginx-tests reads "with OpenSSL <version>" to tell which TLS features there are.
const TLS_LIBRARY: &str = "built with TLS by rustls, compatible with OpenSSL 3.5.7\nTLS SNI support enabled";

#[derive(Debug, PartialEq)]
struct Args {
    prefix: PathBuf,
    conf: PathBuf,
    error_log: PathBuf,
    globals: String,
    version: bool,
    test: bool,
    dump: bool,
    quiet: bool,
    signal: Option<c_int>,
}

const SIGNALS: [(&str, c_int); 4] = [("stop", SIGTERM), ("quit", SIGQUIT), ("reopen", SIGUSR1), ("reload", SIGHUP)];

fn args(list: &[String]) -> Result<Args, String> {
    let mut values = [("-p", "/usr/local/twinx/"), ("-c", "conf/nginx.conf"), ("-e", "logs/error.log"), ("-g", "")].map(|(o, v)| (o, v.to_string()));
    let (mut version, mut test, mut dump, mut quiet, mut signal) = (false, false, false, false, None);
    let mut it = list.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-V" | "-v" => version = true,
            "-t" => test = true,
            "-T" => (test, dump) = (true, true),
            "-q" => quiet = true,
            "-s" => {
                let name = it.next().ok_or("option \"-s\" requires parameter")?;
                signal = Some(SIGNALS.iter().find(|(n, _)| n == name).ok_or_else(|| format!("invalid option: \"-s {name}\""))?.1);
            }
            _ => {
                let slot = values.iter_mut().find(|(o, _)| o == arg).ok_or_else(|| format!("invalid option: \"{arg}\""))?;
                slot.1 = it.next().cloned().ok_or_else(|| format!("option \"{arg}\" requires an argument"))?;
            }
        }
    }
    let [p, c, e, g] = values.map(|(_, v)| v);
    Ok(Args { prefix: p.into(), conf: c.into(), error_log: e.into(), globals: g, version, test, dump, quiet, signal })
}

fn load(a: &Args) -> Result<conf::Config, String> {
    let file = a.prefix.join(&a.conf);
    let text = std::fs::read_to_string(&file).map_err(|e| format!("open() \"{}\" failed ({e})", file.display()))?;
    let mut main = config::parse_in(&a.globals, Path::new("command line"), file.parent().unwrap_or(Path::new("")))?;
    main.extend(config::parse(&text, &file)?);
    if !main.iter().any(|d| d.name == "error_log") { main.extend(config::parse(&format!("error_log \"{}\" error;", a.error_log.display()), &file)?); }
    let config = conf::build(&main, &a.prefix)?;
    config.warnings.iter().for_each(|w| report("warn", w, Some(&a.prefix.join(&a.error_log))));
    spool::make_dirs(&config.temp_paths, config.user.as_ref().map(|u| u.uid))?;
    Ok(config)
}

fn signal_set() -> sigset_t {
    // SAFETY: the set is initialised by sigemptyset before it is used.
    unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [SIGQUIT, SIGTERM, SIGINT, SIGHUP, SIGUSR1] { libc::sigaddset(&mut set, s); }
        set
    }
}

fn wait_signal(set: &sigset_t) -> c_int {
    let mut sig = 0;
    // SAFETY: set is a valid signal set and sig a valid place for the result.
    unsafe { libc::sigwait(set, &mut sig) };
    sig
}

fn run(a: &Args) -> Result<(), String> {
    let mut config = Arc::new(load(a)?);
    shm::share_counters()?;
    let mut listeners = http::bind(&config, &[])?;
    let set = signal_set();
    let mut master = set;
    // SAFETY: the master is single-threaded here; blocking signals has no other effect on it.
    unsafe { libc::sigaddset(&mut master, SIGCHLD); libc::sigprocmask(libc::SIG_BLOCK, &master, std::ptr::null_mut()) };
    if config.daemon { daemon()? }
    let pid = config.pid.clone();
    std::fs::write(&pid, format!("{}\n", std::process::id())).map_err(|e| format!("open() \"{}\" failed ({e})", pid.display()))?;
    let mut workers = spawn(&config, &listeners, &set)?;
    let mut old = Vec::new();
    let sig = loop {
        let sig = wait_signal(&master);
        if sig == SIGCHLD { reap(&config, &listeners, &set, &mut workers, &mut old); continue }
        if sig == SIGUSR1 {
            reopen(&config, config.user.as_ref().map(|u| u.uid));
            // SAFETY: a plain system call on the process ids of the workers.
            workers.iter().for_each(|&w| unsafe { libc::kill(w, SIGUSR1); });
            continue
        }
        if sig != SIGHUP { break sig }
        log(&config.notice_logs, "notice", "reconfiguring");
        let Ok((new, open)) = load(a).map(Arc::new).and_then(|c| Ok((c.clone(), http::bind(&c, &listeners)?))).map_err(|e| emerg(&e, Some(&a.prefix.join(&a.error_log)))) else { continue };
        let replaced = std::mem::replace(&mut workers, spawn(&new, &open, &set)?);
        (config, listeners) = (new, open);
        // SAFETY: a plain system call on the process ids of the workers being replaced.
        replaced.iter().for_each(|&w| unsafe { libc::kill(w, SIGQUIT); });
        old.extend(replaced);
    };
    stop(&config, &[workers, old].concat(), sig);
    let _ = std::fs::remove_file(&pid);
    Ok(())
}

fn daemon() -> Result<(), String> {
    let failed = |call: &str| format!("{call} failed ({})", std::io::Error::last_os_error());
    // SAFETY: the master has no other threads, and the parent only exits.
    match unsafe { libc::fork() } { -1 => return Err(failed("fork()")), 0 => {} _ => std::process::exit(0) }
    // SAFETY: plain system calls on this process and its standard descriptors.
    if unsafe { libc::setsid() } == -1 { return Err(failed("setsid()")) }
    let null = OpenOptions::new().read(true).write(true).open("/dev/null").map_err(|e| format!("open(\"/dev/null\") failed ({e})"))?;
    for (fd, name) in [(0, "STDIN"), (1, "STDOUT")] {
        if unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&null), fd) } == -1 { return Err(failed(&format!("dup2({name})"))) }
    }
    Ok(())
}

fn spawn(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<Vec<pid_t>, String> {
    log(&config.notice_logs, "notice", "start worker processes");
    let mut started = Vec::new();
    for _ in 0..config.workers {
        let w = start(config, listeners, set).inspect_err(|_| stop(config, &started, SIGTERM))?;
        started.push(w);
    }
    Ok(started)
}

fn start(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<pid_t, String> {
    // SAFETY: the master has no other threads, so the child starts in a consistent state.
    let child = unsafe { libc::fork() };
    let w = forked(child, config, listeners, set)?;
    log(&config.notice_logs, "notice", &format!("start worker process {w}"));
    Ok(w)
}

fn reap(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t, workers: &mut Vec<pid_t>, old: &mut Vec<pid_t>) {
    let mut status = 0;
    // SAFETY: waitpid() only writes the status it is given a place for.
    while let pid @ 1.. = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } {
        exited(config, pid, status);
        old.retain(|&w| w != pid);
        let Some(slot) = workers.iter().position(|&w| w == pid) else { continue };
        if libc::WEXITSTATUS(status) == 2 {
            alert(config, &format!("worker process {pid} exited with fatal code 2 and cannot be respawned"));
            workers.remove(slot);
            continue
        }
        match start(config, listeners, set) {
            Ok(w) => workers[slot] = w,
            Err(e) => { alert(config, &e); alert(config, "could not respawn worker process"); workers.remove(slot); }
        }
    }
}

fn stop(config: &conf::Config, workers: &[pid_t], sig: c_int) {
    // SAFETY: plain system calls on the workers' process ids: pass the signal on to all, then wait for each.
    workers.iter().for_each(|&w| unsafe { libc::kill(w, sig); });
    for &w in workers {
        let mut status = 0;
        if unsafe { libc::waitpid(w, &mut status, 0) } == w { exited(config, w, status) }
    }
}

fn exited(config: &conf::Config, pid: pid_t, status: c_int) {
    if libc::WIFSIGNALED(status) {
        let core = if libc::WCOREDUMP(status) { " (core dumped)" } else { "" };
        alert(config, &format!("worker process {pid} exited on signal {}{core}", libc::WTERMSIG(status)))
    } else {
        log(&config.notice_logs, "notice", &format!("worker process {pid} exited with code {}", libc::WEXITSTATUS(status)))
    }
}

/// Not inlined, so that each process counts what it runs here in its own coverage profile.
#[inline(never)]
fn forked(child: pid_t, config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> Result<pid_t, String> {
    if child == 0 { worker(config, listeners, set) }
    (child > 0).then_some(child).ok_or_else(|| format!("fork() failed ({})", std::io::Error::last_os_error()))
}

fn worker(config: &Arc<conf::Config>, listeners: &[(TcpListener, SocketAddr)], set: &sigset_t) -> ! {
    let limit = config.rlimit_nofile.map(|n| libc::rlimit { rlim_cur: n, rlim_max: n });
    // SAFETY: setrlimit() only reads the structure it is given.
    if let Some(l) = limit { unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &l) }; }
    if let Some(u) = &config.user { switch_user(config, u) }
    if let Some((dir, Err(e))) = config.working_directory.as_ref().map(|d| (d, std::env::set_current_dir(d))) {
        let reason = e.to_string().split(" (os error").next().unwrap_or_default().to_string();
        alert(config, &format!("chdir(\"{}\") failed ({}: {reason})", dir.display(), e.raw_os_error().unwrap_or(0)));
        std::process::exit(2)
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap_or_else(|e| fail(&e.to_string(), None));
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let accepting = http::accept(config.clone(), listeners).unwrap_or_else(|e| fail(&e, None));
        let signals = signal_fd(set).unwrap_or_else(|e| fail(&format!("signalfd() failed ({e})"), None));
        let mut sig = SIGHUP;
        while sig == SIGHUP || sig == SIGUSR1 {
            sig = next_signal(&signals).await;
            if sig == SIGUSR1 { reopen(config, None) }
        }
        if sig == SIGQUIT {
            log(&config.notice_logs, "notice", "gracefully shutting down");
            http::shut_down(accepting, config.shutdown_timeout).await
        }
    });
    std::process::exit(0)
}

fn reopen(config: &conf::Config, owner: Option<libc::uid_t>) {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    log(&config.notice_logs, "notice", "reopening logs");
    for (path, file) in &config.logs {
        let new = match OpenOptions::new().create(true).append(true).open(path) {
            Ok(new) => new,
            Err(e) => { log(&config.emerg_logs, "emerg", &spool::failed("open()", path, &e)); continue }
        };
        if let Some(uid) = owner {
            let owned = std::fs::metadata(path).map_err(|e| spool::failed("stat()", path, &e)).and_then(|m| {
                if m.uid() != uid { std::os::unix::fs::chown(path, Some(uid), None).map_err(|e| spool::failed("chown()", path, &e))? }
                if m.mode() & 0o600 != 0o600 { std::fs::set_permissions(path, std::fs::Permissions::from_mode(m.mode() | 0o600)).map_err(|e| spool::failed("chmod()", path, &e))? }
                Ok(())
            });
            if let Err(e) = owned { log(&config.emerg_logs, "emerg", &e); continue }
        }
        // SAFETY: both are open descriptors of this process; the one every holder of the file writes to now names the new file.
        unsafe { libc::dup3(new.as_raw_fd(), file.as_raw_fd(), libc::O_CLOEXEC) };
    }
}

fn switch_user(config: &conf::Config, u: &conf::User) {
    let failed = |call: String| {
        let e = std::io::Error::last_os_error();
        let text = e.to_string();
        log(&config.emerg_logs, "emerg", &format!("{call} failed ({}: {})", e.raw_os_error().unwrap_or(0), text.split(" (os error").next().unwrap_or_default()));
    };
    // SAFETY: plain system calls with ids, and a name ended by a zero byte, that the configuration holds.
    if unsafe { libc::setgid(u.gid) } == -1 { failed(format!("setgid({})", u.gid)); std::process::exit(2) }
    if unsafe { libc::initgroups(u.name.as_ptr(), u.gid) } == -1 { failed(format!("initgroups({}, {})", u.name.to_string_lossy(), u.gid)) }
    if unsafe { libc::setuid(u.uid) } == -1 { failed(format!("setuid({})", u.uid)); std::process::exit(2) }
}

fn signal_fd(set: &sigset_t) -> std::io::Result<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>> {
    use std::os::fd::FromRawFd;
    // SAFETY: set is a valid signal set; the descriptor returned is owned by nothing else.
    let fd = unsafe { libc::signalfd(-1, set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()) }
    // SAFETY: fd is a new descriptor of this process, which the AsyncFd owns and closes.
    unsafe { tokio::io::unix::AsyncFd::register_with_interest(std::os::fd::OwnedFd::from_raw_fd(fd), tokio::io::Interest::READABLE) }.map_err(|e| e.into_parts().1)
}

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
    let a = args(&list).unwrap_or_else(|e| { eprintln!("twinx: {e}"); std::process::exit(1) });
    if a.version {
        eprintln!("twinx version: {}\n{TLS_LIBRARY}\nconfigure arguments: {CONFIGURE}", http::NAME);
        if !a.test { return }
    }
    if a.test { std::process::exit(test(&a)) }
    if let Some(sig) = a.signal { std::process::exit(signal(&a, sig)) }
    if let Err(e) = run(&a) { fail(&e, Some(&a.prefix.join(&a.error_log))) }
}

fn test(a: &Args) -> i32 {
    let file = a.prefix.join(&a.conf);
    if a.dump { config::DUMP.set(Some(Vec::new())) }
    let checked = load(a).and_then(|config| {
        if !a.quiet { eprintln!("twinx: the configuration file {} syntax is ok", file.display()) }
        OpenOptions::new().create(true).write(true).open(&config.pid).map_err(|e| spool::failed("open()", &config.pid, &e))
    });
    if let Err(e) = checked {
        emerg(&e, Some(&a.prefix.join(&a.error_log)));
        eprintln!("twinx: configuration file {} test failed", file.display());
        return 1
    }
    if !a.quiet { eprintln!("twinx: configuration file {} test is successful", file.display()) }
    if a.dump {
        let mut files = vec![(file.clone(), std::fs::read_to_string(&file).unwrap_or_default())];
        files.extend(config::DUMP.take().unwrap_or_default());
        let mut out = std::io::stdout().lock();
        let mut seen = std::collections::HashSet::new();
        for (name, text) in files.iter().filter(|(name, _)| seen.insert(name.clone())) {
            let _ = write!(out, "# configuration file {}:\n{text}\n", name.display());
        }
        let _ = out.flush();
    }
    0
}

fn signal(a: &Args, sig: c_int) -> i32 {
    let log = a.prefix.join(&a.error_log);
    let config = load(a).unwrap_or_else(|e| fail(&e, Some(&log)));
    let pid = &config.pid;
    let text = match std::fs::read(pid) {
        Ok(text) => text,
        Err(e) => { report("error", &spool::failed("open()", pid, &e), Some(&log)); return 1 }
    };
    let text = String::from_utf8_lossy(&text);
    let text = text.trim_end_matches(['\r', '\n']);
    let Some(n) = text.bytes().all(|b| b.is_ascii_digit()).then(|| text.parse::<pid_t>().ok()).flatten() else {
        report("error", &format!("invalid PID number \"{text}\" in \"{}\"", pid.display()), Some(&log));
        return 1
    };
    // SAFETY: kill() takes plain numbers.
    if unsafe { libc::kill(n, sig) } == 0 { return 0 }
    let e = std::io::Error::last_os_error();
    let reason = e.to_string().split(" (os error").next().unwrap_or_default().to_string();
    report("alert", &format!("kill({n}, {sig}) failed ({}: {reason})", e.raw_os_error().unwrap_or(0)), Some(&log));
    1
}

fn fail(msg: &str, log: Option<&Path>) -> ! {
    emerg(msg, log);
    std::process::exit(1)
}

fn alert(config: &conf::Config, msg: &str) {
    log(&config.alert_logs, "alert", msg)
}

fn log(logs: &[Arc<std::fs::File>], level: &str, msg: &str) {
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let line = format!("{time} [{level}] {}#0: {msg}\n", std::process::id());
    logs.iter().for_each(|f| { let _ = (&**f).write_all(line.as_bytes()); });
}

fn emerg(msg: &str, log: Option<&Path>) {
    report("emerg", msg, log)
}

fn report(level: &str, msg: &str, log: Option<&Path>) {
    eprintln!("twinx: [{level}] {msg}");
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let line = format!("{time} [{level}] {}#0: {msg}\n", std::process::id());
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
        let a = args(&strings(&["-T", "-q", "-s", "reopen"])).unwrap();
        assert_eq!((a.test, a.dump, a.quiet, a.signal), (true, true, true, Some(SIGUSR1)));
        assert_eq!(args(&strings(&["-s", "x"])).unwrap_err(), "invalid option: \"-s x\"");
        assert_eq!(args(&strings(&["-s"])).unwrap_err(), "option \"-s\" requires parameter");
        assert_eq!(args(&strings(&["-x"])).unwrap_err(), "invalid option: \"-x\"");
        assert_eq!(args(&strings(&["-p"])).unwrap_err(), "option \"-p\" requires an argument");
    }

    #[test]
    fn alert_goes_to_the_main_error_logs() {
        let dir = std::env::temp_dir().join(format!("twinx-alert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = config::parse("error_log a.log; error_log b.log emerg; events { }", Path::new("t.conf")).unwrap();
        alert(&conf::build(&main, &dir).unwrap(), "chdir(\"wd\") failed");
        let a = std::fs::read_to_string(dir.join("a.log")).unwrap();
        assert!(a.ends_with(&format!(" [alert] {}#0: chdir(\"wd\") failed\n", std::process::id())));
        assert_eq!(std::fs::read_to_string(dir.join("b.log")).unwrap(), "");
    }

    #[test]
    fn takes_blocked_signals() {
        let set = signal_set();
        assert!([SIGQUIT, SIGTERM, SIGINT].iter().all(|&s| unsafe { libc::sigismember(&set, s) } == 1));
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
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50), next_signal(&fd)).await.is_err());
            unsafe { libc::raise(SIGQUIT) };
            assert_eq!(next_signal(&fd).await, SIGQUIT);
        });
    }
}
