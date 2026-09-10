//! `netune-probe`: per-segment capture for one TCP flow (ADR-0200, L2).
//!
//! ```text
//! sudo setcap cap_net_raw+ep target/release/netune-probe
//! netune-probe --interface lo --local 127.0.0.1:51234 --remote 127.0.0.1:443
//! ```
//!
//! Emits one JSON object per segment on stdout, so it composes with anything.
//! `--duration` bounds the run; the probe is a window, not a daemon.

#[cfg(target_os = "linux")]
fn main() {
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            Options::usage();
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("netune-probe: {error}");
            Options::usage();
            std::process::exit(2);
        }
    };

    let mut capture = match netune_probe::capture::Capture::open(
        &options.interface,
        options.local,
        options.remote,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            eprintln!(
                "netune-probe: cannot capture on {}: {error} \
                     (AF_PACKET needs CAP_NET_RAW; run `setcap cap_net_raw+ep <binary>`)",
                options.interface
            );
            std::process::exit(1);
        }
    };

    let deadline = options
        .duration
        .map(|duration| std::time::Instant::now() + duration);
    loop {
        if let Some(deadline) = deadline
            && std::time::Instant::now() >= deadline
        {
            break;
        }
        match capture.next_segment() {
            Ok(segment) => println!(
                "{{\"at_ns\":{},\"dir\":\"{}\",\"len\":{},\"flags\":\"{}\",\"seq\":{},\"ack\":{}}}",
                segment.at_ns,
                if segment.outbound { "out" } else { "in" },
                segment.payload_len,
                flags(&segment),
                segment.seq,
                segment.ack,
            ),
            Err(error) => {
                eprintln!("netune-probe: {error}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn flags(segment: &netune_probe::Segment) -> String {
    use netune_probe::packet::{FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN};
    let mut out = String::new();
    for (flag, letter) in [
        (FLAG_SYN, 'S'),
        (FLAG_ACK, 'A'),
        (FLAG_PSH, 'P'),
        (FLAG_FIN, 'F'),
        (FLAG_RST, 'R'),
    ] {
        if segment.flags & flag != 0 {
            out.push(letter);
        }
    }
    out
}

#[cfg(target_os = "linux")]
struct Options {
    interface: String,
    local: ([u8; 4], u16),
    remote: ([u8; 4], u16),
    duration: Option<std::time::Duration>,
}

#[cfg(target_os = "linux")]
impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut interface = "lo".to_string();
        let mut local = None;
        let mut remote = None;
        let mut duration = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(None),
                "--interface" | "-i" => {
                    interface = args.next().ok_or("--interface needs a value")?;
                }
                "--local" => {
                    local = Some(parse_endpoint(
                        &args.next().ok_or("--local needs a value")?,
                    )?)
                }
                "--remote" => {
                    remote = Some(parse_endpoint(
                        &args.next().ok_or("--remote needs a value")?,
                    )?);
                }
                "--duration" => {
                    let seconds: f64 = args
                        .next()
                        .ok_or("--duration needs a value")?
                        .parse()
                        .map_err(|_| "--duration must be seconds")?;
                    duration = Some(std::time::Duration::from_secs_f64(seconds.max(0.1)));
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Some(Self {
            interface,
            local: local.ok_or("--local is required")?,
            remote: remote.ok_or("--remote is required")?,
            duration,
        }))
    }

    fn usage() {
        println!(
            "netune-probe — per-segment capture for one TCP flow\n\n\
             USAGE:\n  netune-probe --local <ip:port> --remote <ip:port> [--interface <name>] [--duration <secs>]\n\n\
             Requires CAP_NET_RAW: sudo setcap cap_net_raw+ep <binary>"
        );
    }
}

#[cfg(target_os = "linux")]
fn parse_endpoint(text: &str) -> Result<([u8; 4], u16), String> {
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| format!("expected ip:port, got {text}"))?;
    let ip = netune_probe::capture::parse_ipv4(host)
        .ok_or_else(|| format!("expected an IPv4 literal, got {host}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid port in {text}"))?;
    Ok((ip, port))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "netune-probe: AF_PACKET capture is Linux-only; the syscall tap (L1) \
         remains available on this platform"
    );
    std::process::exit(1);
}
