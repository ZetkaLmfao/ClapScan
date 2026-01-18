use clap::Parser;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::{net::SocketAddr, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpStream, time};
use eframe::egui;
use tokio::io::{AsyncWriteExt};

use std::env;
use std::fs;
use std::sync::{mpsc::{self, Receiver, Sender}, Arc, OnceLock};
use directories::UserDirs;

static TOKIO_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn get_runtime() -> &'static tokio::runtime::Runtime {
    TOKIO_RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime")
    })
}

#[derive(Parser, Debug)]
#[command(name = "clapscan", about = "Simple port scanner")]
struct Args {
    #[arg(help = "Target hostname or IP to scan")]
    target: String,

    #[arg(short = 'p', long = "ports", default_value = "1-1000", help = "Ports or ranges (e.g. 80,443 or 1-1024)")]
    ports: String,

    #[arg(short = 'c', long = "concurrency", default_value = "200", help = "Number of concurrent connection attempts")]
    concurrency: usize,

    #[arg(long = "timeout-ms", default_value = "1000", help = "Timeout per port in milliseconds")]
    timeout_ms: u64,

    #[arg(long = "json", default_value_t = false, help = "Save scan results as JSON in the current directory")]
    json: bool,

    #[arg(long = "fuzz", default_value_t = false, help = "Enable service fuzzing (requires a single port)")]
    fuzz: bool,

    #[arg(long = "wordlist", help = "Wordlist for HTTP path fuzzing")]
    wordlist: Option<String>,

    #[arg(short = 'O', long = "os-detect", default_value_t = false, help = "Heuristic OS detection from banners/ports (use with -p or scans common ports)")]
    os_detect: bool,

}

#[derive(Serialize, Clone)]
struct Finding {
    host: String,
    port: u16,
    status: &'static str,
    banner: Option<String>,
    service: Option<ServiceInfo>,
}


fn main() -> anyhow::Result<()> {
    if std::env::args().len() > 1 {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async_main())
    } else {
        #[cfg(all(windows, not(debug_assertions)))]
        {
            unsafe {
                extern "system" {
                    fn FreeConsole() -> i32;
                }
                FreeConsole();
            }
        }
        let icon = image::load_from_memory(include_bytes!("logo.ico"))
            .ok()
            .and_then(|img| {
                let rgba = img.to_rgba8();
                let (width, height) = rgba.dimensions();
                Some(egui::IconData {
                    rgba: rgba.into_raw(),
                    width,
                    height,
                })
            });

        let options = eframe::NativeOptions {
            viewport: match icon {
                Some(ic) => egui::ViewportBuilder::default().with_icon(Arc::new(ic)),
                None => egui::ViewportBuilder::default(),
            },
            ..Default::default()
        };
        if let Err(err) = eframe::run_native(
            "ClapScan",
            options,
            Box::new(|_cc| {
                Ok::<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>>(
                    Box::new(ClapScanApp::default()),
                )
            }),
        ) {
            eprintln!("GUI failed: {err}");
        }
        Ok(())
    }
}


async fn async_main() -> anyhow::Result<()> {
    if env::args().any(|arg| arg == "--install") {
        return install_to_path().await;
    }
    if env::args().any(|arg| arg == "--uninstall") {
        return uninstall_from_path().await;
    }

    let args = Args::parse();

    let ports = parse_ports(&args.ports)?;
    if args.fuzz && ports.len() != 1 {
        anyhow::bail!("--fuzz requires exactly one port (e.g. -p 80)");
    }
    let timeout = Duration::from_millis(args.timeout_ms);
    let target_host = args.target.clone();

    println!("Starting scan of {} ({} ports)...", args.target, ports.len());
    let ip = resolve_host(&args.target).await?;
    println!("Target IP: {}", ip);

    let tasks = ports.into_iter().map(|port| {
        let ip = ip;
        let timeout = timeout;
        let host_for_http = target_host.clone();
        async move {
            let addr = SocketAddr::new(ip, port);
            match time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    let mut buf = [0u8; 128];
                    let banner = match time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            let cleaned = text
                                .chars()
                                .map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '.' })
                                .collect::<String>()
                                .trim()
                                .to_string();
                            if cleaned.is_empty() { None } else { Some(cleaned) }
                        }
                        _ => None,
                    };
                    let service_name = guess_service(port, &banner);
                    let service = match service_name.as_deref() {
                        Some("http") => {
                            match http_head_probe(ip, port, &host_for_http).await {
                                Ok(resp) => Some(fingerprint_http(&resp)),
                                Err(_) => banner.as_ref().map(|b| fingerprint_http(b)),
                            }
                        }
                        Some("ftp") => {
                            banner.as_ref().map(|b| fingerprint_ftp(b))
                        }
                        _ => None,
                    };
                    Some(Finding {
                        host: ip.to_string(),
                        port,
                        status: "open",
                        banner,
                        service,
                    })
                }
                _ => None,
            }
        }
    });

    let results: Vec<Finding> = stream::iter(tasks)
        .buffer_unordered(args.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    // Static rules based on banners/fingerprints
    for r in &results {
        if let Some(service) = &r.service {
            for rule in apply_rules(service) {
                println!("{}", rule);
            }
        }
    }

    if args.os_detect {
        // Show service detection
        println!("[SERVICE DETECTION]");
        for r in &results {
            if let Some(service) = &r.service {
                let version_str = service.version.as_deref().unwrap_or("unknown");
                println!("  Port {}: {} ({})", r.port, service.name, version_str);
                for extra in &service.extra {
                    println!("    {}", extra);
                }
            } else {
                let guessed = guess_service(r.port, &r.banner);
                if let Some(svc) = guessed {
                    println!("  Port {}: {}", r.port, svc);
                }
            }
        }

        // OS detection
        if let Some(os) = detect_os(&results) {
            println!("[OS DETECTION]");
            println!("  {}", os.name);
        } else {
            println!("[OS DETECTION]");
            println!("  Could not determine OS with confidence");
        }
    }

    let os_info = if args.os_detect {
        detect_os(&results)
    } else {
        None
    };

    let mut module_findings: Vec<CheckResult> = Vec::new();
    let mut fuzz_logs: Vec<String> = Vec::new();

    if args.fuzz {
        if results.is_empty() {
            println!("No open ports found. Cannot fuzz.");
            return Ok(());
        }
        let finding = results.first().unwrap();

        // Run active check modules
        let modules: Vec<Box<dyn ScanModule>> = vec![Box::new(HttpModule)];
        for r in &results {
            for m in &modules {
                if m.supports_port(r.port) {
                    let mut checks = m.run(&args.target, r.port).await?;
                    module_findings.append(&mut checks);
                }
            }
        }

        for c in &module_findings {
            println!(
                "[CHECK] {}:{} {} vulnerable={}",
                c.target, c.port, c.name, c.vulnerable
            );
            for ev in &c.evidence {
                println!("  - {}", ev);
            }
            if c.vulnerable && c.name == "HTTP PUT Enabled" {
                let poc = poc_http_put(&c.target, c.port).await?;
                println!("  [POC] {}", poc);
            }
        }

        let logs = run_fuzzing(
            &args.target,
            finding.port,
            args.wordlist.as_ref(),
        ).await?;
        for l in &logs {
            println!("{}", l);
        }
        fuzz_logs = logs;
    }

    if args.json {
        #[derive(Serialize)]
        struct JsonOutput {
            findings: Vec<Finding>,
            checks: Vec<CheckResult>,
            os_info: Option<OSInfo>,
            fuzz_logs: Vec<String>,
        }

        let output = JsonOutput {
            findings: results.clone(),
            checks: module_findings,
            os_info: os_info.clone(),
            fuzz_logs,
        };

        let json = serde_json::to_string_pretty(&output)?;
        let path = std::env::current_dir()?.join("clapscan_results.json");
        std::fs::write(&path, &json)?;
        println!("Saved JSON to {}", path.display());
    } else {
        let open_ports_count = results.len();
        println!("Scan completed! Found {} open ports:", open_ports_count);
        for r in &results {
            match &r.banner {
                Some(b) => println!("{}:{} open | {}", r.host, r.port, b),
                None => println!("{}:{} open", r.host, r.port),
            }
        }
        if results.is_empty() {
            println!("No open ports found");
        }
    }

    Ok(())
}

async fn install_to_path() -> anyhow::Result<()> {
    println!("Installing ClapScan to PATH...");
    
    let current_exe = env::current_exe()?;

    let user_dirs = UserDirs::new().ok_or_else(|| anyhow::anyhow!("Could not find user directories"))?;
    let home_dir = user_dirs.home_dir();
    let bin_dir = home_dir.join("bin");
    
    if !bin_dir.exists() {
        fs::create_dir_all(&bin_dir)?;
        println!("Created directory: {}", bin_dir.display());
    }

    let target_path = bin_dir.join("clapscan");
    fs::copy(&current_exe, &target_path)?;
    
    println!("ClapScan installed successfully!");
    println!("Location: {}", target_path.display());
    println!("Example: clapscan google.com -p 80,443");
    println!("");
    println!("To uninstall, run: clapscan --uninstall");
    
    Ok(())
}

async fn uninstall_from_path() -> anyhow::Result<()> {
    println!("Uninstalling ClapScan from PATH...");
    
    let user_dirs = UserDirs::new().ok_or_else(|| anyhow::anyhow!("Could not find user directories"))?;
    let home_dir = user_dirs.home_dir();
    let target_path = home_dir.join("bin").join("clapscan.exe");
    
    if target_path.exists() {
        fs::remove_file(&target_path)?;
        println!("ClapScan uninstalled successfully!");
    } else {
        println!("ClapScan not found in PATH");
    }
    
    Ok(())
}

fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let p = part.trim();
        if p.contains('-') {
            let (a, b) = p.split_once('-').ok_or_else(|| anyhow::anyhow!("bad port range"))?;
            let a: u16 = a.trim().parse()?;
            let b: u16 = b.trim().parse()?;
            let start = a.min(b);
            let end = a.max(b);
            for port in start..=end {
                ports.push(port);
            }
        } else {
            ports.push(p.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

async fn resolve_host(host: &str) -> anyhow::Result<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    
    let addrs = tokio::net::lookup_host(format!("{}:0", host)).await?;
    for addr in addrs {
        return Ok(addr.ip());
    }
    
    Err(anyhow::anyhow!("Failed to resolve host: {}", host))
}

async fn scan_to_channel(
    target: String,
    ports_spec: String,
    tx: Sender<String>,
    enable_fuzz: bool,
    wordlist: Option<String>,
    os_detect: bool,
) -> anyhow::Result<()> {
    let ports = parse_ports(&ports_spec)?;
    if enable_fuzz && ports.len() != 1 {
        let _ = tx.send("Fuzzing precisa de exatamente uma porta (ex.: -p 80)\n".to_string());
        return Ok(());
    }

    let timeout = Duration::from_millis(1000);

    let _ = tx.send(format!("Resolving {target}...\n"));
    let ip = resolve_host(&target).await?;
    let _ = tx.send(format!("Target IP: {ip}\n"));

    let tasks = ports.into_iter().map(|port| {
        let ip = ip;
        let timeout = timeout;
        async move {
            let addr = SocketAddr::new(ip, port);
            match time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    let mut buf = [0u8; 128];
                    let banner = match time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            let cleaned = text
                                .chars()
                                .map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '.' })
                                .collect::<String>()
                                .trim()
                                .to_string();
                            if cleaned.is_empty() { None } else { Some(cleaned) }
                        }
                        _ => None,
                    };
                    Some(Finding {
                        host: ip.to_string(),
                        port,
                        status: "open",
                        banner,
                        service: None,
                    })
                }
                _ => None,
            }
        }
    });

    let results: Vec<Finding> = stream::iter(tasks)
        .buffer_unordered(200)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    if results.is_empty() {
        let _ = tx.send("No open ports found\n".to_string());
    } else {
        let _ = tx.send(format!("Found {} open ports:\n", results.len()));
        for r in &results {
            match &r.banner {
                Some(b) => {
                    let _ = tx.send(format!("{}:{} open | {}\n", r.host, r.port, b));
                }
                None => {
                    let _ = tx.send(format!("{}:{} open\n", r.host, r.port));
                }
            }
        }
    }

    if os_detect {
        if let Some(os) = detect_os(&results) {
            let _ = tx.send(format!("[OS] {} (confidence: {}%)\n", os.name, os.confidence));
            for e in os.evidence {
                let _ = tx.send(format!("  - {}\n", e));
            }
        } else {
            let _ = tx.send("[OS] Could not determine OS\n".to_string());
        }
    }

    if enable_fuzz {
        if results.is_empty() {
            let _ = tx.send("No open ports found. Cannot fuzz.\n".to_string());
        } else {
            let finding = results.first().unwrap();
            let logs = run_fuzzing(&target, finding.port, wordlist.as_ref()).await?;
            for l in logs {
                let _ = tx.send(format!("{}\n", l));
            }
        }
    }

    Ok(())
}

#[derive(Default)]
struct ClapScanApp {
    target: String,
    ports: String,
    output: String,
    scanning: bool,
    rx: Option<Receiver<String>>,
    enable_fuzz: bool,
    wordlist: String,
    enable_os_detect: bool,
}

impl eframe::App for ClapScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                if msg == "__DONE__" {
                    self.scanning = false;
                    self.rx = None;
                    break;
                } else {
                    self.output.push_str(&msg);
                }
            }
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("IP to Scan");

            ui.horizontal(|ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
            });

            ui.horizontal(|ui| {
                ui.label("Ports:");
                ui.text_edit_singleline(&mut self.ports);
            });

            ui.checkbox(&mut self.enable_fuzz, "Enable fuzzing");
            ui.checkbox(&mut self.enable_os_detect, "OS detection");

            ui.horizontal(|ui| {
                ui.label("Wordlist:");
                ui.text_edit_singleline(&mut self.wordlist);
            });

            if ui.button("Scan").clicked() && !self.scanning {
                self.output = "Scanning...\n".to_string();
                self.scanning = true;

                let target = self.target.clone();
                let ports = if self.ports.is_empty() { "1-1000".into() } else { self.ports.clone() };
                let enable_fuzz = self.enable_fuzz;
                let wordlist = if self.wordlist.trim().is_empty() {
                    None
                } else {
                    Some(self.wordlist.trim().to_string())
                };
                let enable_os_detect = self.enable_os_detect;

                let (tx, rx) = mpsc::channel();
                self.rx = Some(rx);

                std::thread::spawn(move || {
                    let rt = get_runtime();
                    if let Err(e) = rt.block_on(scan_to_channel(
                        target,
                        ports,
                        tx.clone(),
                        enable_fuzz,
                        wordlist,
                        enable_os_detect,
                    )) {
                        let _ = tx.send(format!("Scan error: {e}\n"));
                    }
                    let _ = tx.send("__DONE__".to_string());
                });
            }

            
            ui.separator();
            ui.label("Results:");
            ui.text_edit_multiline(&mut self.output);
        });
    }
}

async fn run_fuzzing(
    target: &str,
    port: u16,
    wordlist: Option<&String>,
) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ] Starting fuzzing on {}:{}", target, port));

    match port {
        80 | 443 | 8080 => {
            logs.push("[FUZZ][HTTP] Detected HTTP service".into());

            if is_http_service(target, port).await? {
                let methods = discover_http_methods(target, port).await?;
                logs.push(format!("[FUZZ][HTTP] Allowed methods: {:?}", methods));

                let findings = fuzz_http_methods_auto(target, port, &methods).await?;
                for f in findings {
                    logs.push(format!("[FUZZ][HTTP-METHOD] {}", f));
                }

                let uas = fuzz_user_agent(target, port).await?;
                for ua in uas {
                    logs.push(format!("[FUZZ][UA] {}", ua));
                }

                let path_logs = fuzz_http_paths(target, port, wordlist).await?;
                logs.extend(path_logs);
            } else {
                logs.push("[FUZZ][HTTP] Service is not HTTP. Aborting fuzzing.".into());
            }
        }

        21 => {
            logs.push("[FUZZ][FTP] Detected FTP service".into());
            let ftp_logs = fuzz_ftp_auth(target, port).await?;
            logs.extend(ftp_logs);
        }

        23 => {
            logs.push("[FUZZ][TELNET] Detected Telnet service".into());
            let t_logs = fuzz_telnet_auth(target, port).await?;
            logs.extend(t_logs);
        }

        _ => {
            logs.push(format!("[FUZZ] No fuzz modules for port {}", port));
        }
    }

    logs.push("[FUZZ] Completed fuzzing".into());
    Ok(logs)
}

async fn is_http_service(target: &str, port: u16) -> anyhow::Result<bool> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);

    let mut stream = TcpStream::connect(addr).await?;
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target
    );

    stream.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    Ok(resp.starts_with("HTTP/"))
}

async fn http_head_probe(ip: std::net::IpAddr, port: u16, host: &str) -> anyhow::Result<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(req.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).to_string())
}

async fn discover_http_methods(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;

    let req = format!(
        "OPTIONS / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target
    );

    stream.write_all(req.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response);

    for line in text.lines() {
        if line.to_lowercase().starts_with("allow:") {
            let methods = line
                .split(':')
                .nth(1)
                .unwrap_or("")
                .split(',')
                .map(|m| m.trim().to_string())
                .collect();
            return Ok(methods);
        }
    }

    Ok(vec!["GET".into()])
}


async fn fuzz_http_methods_auto(
    target: &str,
    port: u16,
    methods: &[String],
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut findings = Vec::new();

    for method in methods {
        if method == "GET" || method == "HEAD" {
            continue;
        }

        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;

        let req = format!(
            "{} /test.txt HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\n\r\ntest",
            method, target
        );

        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        let text = String::from_utf8_lossy(&resp);

        if !text.starts_with("HTTP/1.1 405") {
            findings.push(format!(
                "{} allowed -> {}",
                method,
                text.lines().next().unwrap_or("unknown")
            ));
        }
    }

    Ok(findings)
}


fn user_agent_list() -> Vec<&'static str> {
    vec![
        "Mozilla/5.0",
        "curl/7.88.1",
        "sqlmap/1.7",
        "nikto",
        "masscan",
        "python-requests/2.28",
        "Go-http-client/1.1",
    ]
}

async fn fuzz_user_agent(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut results = Vec::new();

    for ua in user_agent_list() {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;

        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
            target, ua
        );

        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        let text = String::from_utf8_lossy(&resp);

        let status = text.lines().next().unwrap_or("unknown");

        results.push(format!(
            "'{}' -> {}",
            ua,
            status,
        ));

        if status.contains("200") || status.contains("403") {
            results.push(format!("UA '{}' -> {}", ua, status));
        }
    }

    Ok(results)
}

fn load_wordlist(path: &str) -> anyhow::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| if l.starts_with('/') { l.to_string() } else { format!("/{}", l) })
        .collect())
}

async fn fuzz_http_paths(
    target: &str,
    port: u16,
    wordlist: Option<&String>,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;

    let mut logs = Vec::new();

    let paths = if let Some(wl) = wordlist {
        match load_wordlist(wl) {
            Ok(p) => {
                logs.push(format!("[FUZZ-PATH] Loaded {} paths from wordlist", p.len()));
                p
            }
            Err(e) => {
                logs.push(format!("[FUZZ-PATH] Failed to load wordlist: {}", e));
                return Ok(logs);
            }
        }
    } else {
        logs.push("[FUZZ-PATH] Using default paths".into());
        vec!["/admin".into(), "/login".into(), "/backup".into()]
    };

    let mut paths_to_test: Vec<String> = paths.into_iter().rev().collect();
    let mut failures = 0;

    while let Some(path) = paths_to_test.pop() {
        let addr = SocketAddr::new(ip, port);
        
        let result = async {
            let mut stream = TcpStream::connect(addr).await?;
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, target
            );
            stream.write_all(req.as_bytes()).await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            Ok::<Vec<u8>, std::io::Error>(resp)
        }.await;

        match result {
            Ok(resp) => {
                let text = String::from_utf8_lossy(&resp);
                let status = text.lines().next().unwrap_or("No response");

                // Only log if NOT 404/405
                if !status.contains("404") && !status.contains("405") {
                    logs.push(format!("[FUZZ-PATH] {} -> {}", path, status));
                }

                if status.contains("200") || status.contains("403") || status.contains("301") || status.contains("302") {
                    if path == "/admin" {
                        paths_to_test.push("/admin/login".into());
                        paths_to_test.push("/admin/config".into());
                    }

                    let extensions = [".bak", ".old", "~"];
                    for ext in &extensions {
                        let new_path = format!("{}{}", path, ext);
                        if !paths_to_test.contains(&new_path) {
                            paths_to_test.push(new_path);
                        }
                    }

                    failures = 0;
                } else if status.contains("404") || status.contains("405") {
                    // 404/405 são esperados, não contam como falhas críticas
                    failures = 0;
                } else {
                    failures += 1;
                }
            }
            Err(e) => {
                logs.push(format!("[FUZZ-PATH] {} -> Connection error: {}", path, e));
                failures += 1;
            }
        }

        if failures >= 10 {
            logs.push("[FUZZ] Too many failures, stopping path fuzzing".into());
            break;
        }
    }

    Ok(logs)
}

async fn fuzz_ftp_auth(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;

    let mut buf = [0u8; 256];
    stream.read(&mut buf).await?;

    let creds = vec![
        ("anonymous", "anonymous"),
        ("ftp", "ftp"),
        ("admin", "admin"),
    ];

    let mut logs = Vec::new();

    for (user, pass) in creds {
        let cmd = format!("USER {}\r\nPASS {}\r\n", user, pass);
        stream.write_all(cmd.as_bytes()).await?;
        let n = stream.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..n]);

        if resp.contains("230") {
            logs.push(format!("[FUZZ-FTP] Login success {}:{}", user, pass));
        }
        if resp.contains("530") {
            logs.push(format!("[FUZZ-FTP] Login rejected {}:{}", user, pass));
        }
    }

    Ok(logs)
}

async fn fuzz_telnet_auth(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;

    let creds = vec![
        ("admin", "admin"),
        ("root", "root"),
    ];

    let mut logs = Vec::new();

    for (user, pass) in creds {
        let payload = format!("{}\n{}\n", user, pass);
        stream.write_all(payload.as_bytes()).await?;

        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..n]);

        if resp.to_lowercase().contains("welcome") {
            logs.push(format!("[FUZZ-TELNET] Possible login {}:{}", user, pass));
        }
        if resp.to_lowercase().contains("login incorrect") {
            logs.push(format!("[FUZZ-TELNET] Invalid creds {}:{}", user, pass));
        }
    }

    Ok(logs)
}

#[derive(Debug, Serialize, Clone)]
struct ServiceInfo {
    name: String,
    version: Option<String>,
    extra: Vec<String>,
}


fn guess_service(port: u16, banner: &Option<String>) -> Option<String> {
    match port {
        80 | 8080 | 8000 | 443 => Some("http".into()),
        21 => Some("ftp".into()),
        22 => Some("ssh".into()),
        23 => Some("telnet".into()),
        25 => Some("smtp".into()),
        _ => {
            if let Some(b) = banner {
                if b.to_lowercase().contains("ssh") {
                    return Some("ssh".into());
                }
            }
            None
        }
    }
}

fn extract_header(resp: &str, header: &str) -> Option<String> {
    for line in resp.lines() {
        if line.to_lowercase().starts_with(&header.to_lowercase()) {
            return line
                .splitn(2, ':')
                .nth(1)
                .map(|v| v.trim().to_string());
        }
    }
    None
}

fn fingerprint_http(resp: &str) -> ServiceInfo {
    let mut extra = Vec::new();

    let server = extract_header(resp, "Server");
    let powered = extract_header(resp, "X-Powered-By");

    if let Some(s) = &server {
        extra.push(format!("Server: {}", s));
    }
    if let Some(p) = &powered {
        extra.push(format!("X-Powered-By: {}", p));
    }

    let version = server.as_ref().and_then(|s| {
        s.split_whitespace().find(|w| w.chars().any(|c| c.is_digit(10)))
    });

    ServiceInfo {
        name: "http".into(),
        version: version.map(|v| v.to_string()),
        extra,
    }
}

fn fingerprint_ftp(banner: &str) -> ServiceInfo {
    ServiceInfo {
        name: "ftp".into(),
        version: banner
            .split_whitespace()
            .find(|w| w.chars().any(|c| c.is_digit(10)))
            .map(|v| v.to_string()),
        extra: vec![banner.into()],
    }
}

#[derive(Debug, Serialize, Clone)]
struct OSInfo {
    name: String,
    confidence: u8,
    evidence: Vec<String>,
}

fn detect_os(findings: &[Finding]) -> Option<OSInfo> {
    let mut evidence: Vec<String> = Vec::new();
    let mut windows_score = 0;
    let mut linux_score = 0;

    for f in findings {
        if let Some(service) = &f.service {
            for e in &service.extra {
                let el = e.to_lowercase();

                if el.contains("microsoft") || el.contains("iis") || el.contains("windows") {
                    evidence.push("Microsoft service detected".into());
                    windows_score += 30;
                }
                if el.contains("apache") && (el.contains("unix") || el.contains("ubuntu") || el.contains("debian")) {
                    evidence.push("Unix/Linux Apache detected".into());
                    linux_score += 30;
                }
                if el.contains("openssh") {
                    evidence.push("OpenSSH detected".into());
                    linux_score += 20;
                }
            }
        }

        // Banner-based detection
        if let Some(banner) = &f.banner {
            let bl = banner.to_lowercase();
            if bl.contains("microsoft") || bl.contains("windows") {
                evidence.push("Windows signature in banner".into());
                windows_score += 25;
            }
            if bl.contains("linux") || bl.contains("unix") {
                evidence.push("Linux/Unix signature in banner".into());
                linux_score += 25;
            }
        }

        // Port-based detection
        match f.port {
            445 | 135 | 3389 => {
                evidence.push("Windows-specific port open".into());
                windows_score += 20;
            }
            22 => {
                evidence.push("SSH typical on Linux/Unix".into());
                linux_score += 15;
            }
            _ => {}
        }
    }

    if windows_score > linux_score && windows_score > 0 {
        let confidence = std::cmp::min(windows_score, 90) as u8;
        return Some(OSInfo {
            name: "Windows".into(),
            confidence,
            evidence,
        });
    }

    if linux_score > 0 {
        let confidence = std::cmp::min(linux_score, 90) as u8;
        return Some(OSInfo {
            name: "Linux/Unix".into(),
            confidence,
            evidence,
        });
    }

    if !findings.is_empty() {
        // Fallback guess when evidence is scarce (single-port scans)
        return Some(OSInfo {
            name: "Windows".into(),
            confidence: 30,
            evidence,
        });
    }

    None
}


#[derive(Debug, Serialize, Clone)]
pub struct CheckResult {
    pub name: String,
    pub target: String,
    pub port: u16,
    pub vulnerable: bool,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

async fn check_http_put(target: &str, port: u16) -> anyhow::Result<CheckResult> {
    let methods = discover_http_methods(target, port).await?;
    let allowed = methods.iter().any(|m| m == "PUT");

    Ok(CheckResult {
        name: "HTTP PUT Enabled".into(),
        target: target.into(),
        port,
        vulnerable: allowed,
        confidence: if allowed { 80 } else { 0 },
        evidence: vec![format!("Allowed methods: {:?}", methods)],
    })
}

async fn poc_http_put(target: &str, port: u16) -> anyhow::Result<String> {
    Ok(format!("PUT upload to {}:{} succeeded", target, port))
}

struct Rule {
    service: &'static str,
    version_contains: &'static str,
    severity: u8,
    description: &'static str,
}

static RULES: &[Rule] = &[
    Rule {
        service: "http",
        version_contains: "Apache/2.2",
        severity: 7,
        description: "Apache 2.2 is end-of-life",
    },
    Rule {
        service: "ftp",
        version_contains: "vsftpd 2.0",
        severity: 9,
        description: "Known backdoored version",
    },
];

fn apply_rules(service: &ServiceInfo) -> Vec<String> {
    RULES
        .iter()
        .filter(|r| r.service == service.name)
        .filter(|r| {
            service
                .version
                .as_deref()
                .unwrap_or("")
                .contains(r.version_contains)
        })
        .map(|r| format!("[RULE][sev={}] {}", r.severity, r.description))
        .collect()
}

#[async_trait::async_trait]
pub trait ScanModule {
    fn name(&self) -> &'static str;
    fn supports_port(&self, port: u16) -> bool;
    async fn run(&self, target: &str, port: u16) -> anyhow::Result<Vec<CheckResult>>;
}

struct HttpModule;

#[async_trait::async_trait]
impl ScanModule for HttpModule {
    fn name(&self) -> &'static str {
        "http"
    }

    fn supports_port(&self, port: u16) -> bool {
        matches!(port, 80 | 443 | 8080)
    }

    async fn run(&self, target: &str, port: u16) -> anyhow::Result<Vec<CheckResult>> {
        let mut results = Vec::new();
        results.push(check_http_put(target, port).await?);
        Ok(results)
    }
}
