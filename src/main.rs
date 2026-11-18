use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" if i + 1 < args.len() => {
                config_path = Some(args[i + 1].clone());
                i += 2;
            }
            "-v" | "-V" => {
                eprintln!("twinx version: twinx/{}", twinx::VERSION);
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("twinx: invalid option: \"{other}\"");
                return ExitCode::from(1);
            }
        }
    }
    let path = config_path.unwrap_or_else(|| "/etc/nginx/nginx.conf".to_string());
    let config = match twinx::config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("twinx: [emerg] {error}");
            return ExitCode::from(1);
        }
    };
    match twinx::server::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("twinx: [emerg] {error}");
            ExitCode::from(1)
        }
    }
}
