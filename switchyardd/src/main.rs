mod alias;
mod config;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path = String::from("/etc/relayfabric/relayfabric.yaml");
    let mut check_only = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next().expect("--config needs a path"),
            "--check-config" => check_only = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let cfg = match config::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    if check_only {
        println!("configuration valid: {} route(s), {} plugin(s)",
                 cfg.routes.len(), cfg.plugins.len());
        return;
    }
    let _ = cfg; // daemon startup arrives in Task 9
}
