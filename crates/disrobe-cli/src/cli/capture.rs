use std::path::{Path, PathBuf};

use disrobe_dataforensics::capture::{CaptureOptions, CaptureReport, inspect};

use crate::cli::output::{self, OutputFormat};

const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) fn run(
    path: PathBuf,
    extract: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(&path)
        .map_err(|e| miette::miette!("DR-CLI-0442: cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_CAPTURE_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0442: {} is {size} bytes, above the {MAX_CAPTURE_BYTES}-byte limit",
            path.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0442: cannot read {}: {e}", path.display()))?;
    let options: CaptureOptions = CaptureOptions {
        keep_bodies: extract.is_some(),
        ..CaptureOptions::default()
    };
    let report: CaptureReport = inspect(&bytes, &options)
        .map_err(|e| miette::miette!("DR-CLI-0443: {}: {e}", path.display()))?;
    if let Some(dir) = &extract {
        write_bodies(&report, dir)?;
    }
    output::emit(fmt, &report, || render(&report, extract.as_deref()))?;
    Ok(())
}

fn write_bodies(report: &CaptureReport, dir: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| miette::miette!("DR-CLI-0444: cannot create {}: {e}", dir.display()))?;
    for body in &report.bodies {
        let extension: &str = match body
            .content_type
            .as_deref()
            .map(|t: &str| t.split(';').next().unwrap_or_default().trim())
        {
            Some("text/html") => "html",
            Some("application/json") => "json",
            Some("application/javascript" | "text/javascript") => "js",
            Some("text/plain") => "txt",
            Some("image/png") => "png",
            Some("image/jpeg") => "jpg",
            _ => "bin",
        };
        let target: PathBuf = dir.join(format!("exchange-{:05}.{extension}", body.exchange));
        std::fs::write(&target, &body.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0444: cannot write {}: {e}", target.display()))?;
    }
    Ok(())
}

fn render(report: &CaptureReport, extract: Option<&Path>) {
    println!(
        "capture: {:?}, {} frames, {} flows, {} DNS messages, {} TLS client hellos, {} HTTP exchanges",
        report.format,
        report.frames,
        report.flows.len(),
        report.dns.len(),
        report.tls.len(),
        report.http.len()
    );
    for (protocol, count) in &report.protocols {
        println!("  {protocol:<16} {count}");
    }
    for flow in &report.flows {
        println!(
            "  {} {} -> {} ({} packets, {}/{} bytes){}{}",
            flow.protocol,
            flow.client,
            flow.server,
            flow.packets,
            flow.client_bytes,
            flow.server_bytes,
            flow.application
                .as_deref()
                .map(|app: &str| format!(" [{app}]"))
                .unwrap_or_default(),
            if flow.stream_complete {
                ""
            } else {
                " (stream has gaps)"
            }
        );
    }
    for event in &report.dns {
        for question in &event.message.questions {
            println!(
                "  dns {} {} type {}",
                event.client, question.name, question.qtype
            );
        }
        for answer in &event.message.answers {
            println!(
                "    {} -> {} (type {})",
                answer.name, answer.data, answer.rtype
            );
        }
    }
    for tls in &report.tls {
        println!(
            "  tls {} -> {} sni={} alpn={} ja3={}",
            tls.client,
            tls.server,
            tls.hello.sni.as_deref().unwrap_or("-"),
            tls.hello.alpn.join(","),
            tls.hello.ja3_md5
        );
    }
    for exchange in &report.http {
        println!(
            "  http {} {} {} -> {}",
            exchange.method,
            exchange.host.as_deref().unwrap_or("-"),
            exchange.target,
            exchange
                .status
                .map_or_else(|| "-".to_owned(), |code: u16| code.to_string())
        );
    }
    if let Some(dir) = extract {
        println!(
            "  bodies:       {} written to {}",
            report.bodies.len(),
            dir.display()
        );
    }
    for problem in &report.problems {
        println!("  problem:      {problem}");
    }
}
