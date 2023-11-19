use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Lines};
use std::iter::Peekable;

pub mod nmapmatch;
pub mod probe;

use nmapmatch::{parse_match_line, MatchLine};
use probe::Probe;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ProbeDirectives {
    matches: Option<Vec<nmapmatch::MatchLine>>,
    soft_matches: Option<Vec<nmapmatch::MatchLine>>,
    ports: Option<Vec<u16>>,
    ssl_ports: Option<Vec<u16>>,
    total_wait_ms: Option<usize>,
    tcp_wrapped_ms: Option<usize>,
    rarity: Option<usize>,
    fallback: Option<Vec<String>>,
}

impl ProbeDirectives {
    fn new() -> ProbeDirectives {
        Self {
            matches: None,
            soft_matches: None,
            ports: None,
            ssl_ports: None,
            total_wait_ms: None,
            tcp_wrapped_ms: None,
            rarity: None,
            fallback: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ServiceProbes {
    tcp_probes: Vec<ServiceProbe>,
    udp_probes: Vec<ServiceProbe>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ServiceProbe {
    probe: Probe,
    directives: ProbeDirectives,
}

pub fn read_service_probes_file(f: &str) {
    let f =
        File::open(f).unwrap_or_else(|_| panic!("failed to read nmap_service_probes file {}", f));
    let mut lines = BufReader::new(f).lines();
    while let Some(line) = lines.next() {
        let line = line.expect("failed to read line");
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        } else if line.starts_with("Probe") {
            let probe = probe::parse_probe_line(&line)
                .unwrap_or_else(|| panic!("failed to parse probe line {}", &line));
            let directives = read_probe_directives(&mut lines);
        }
    }
}

// Read the ports, sslports, totalwaitms, tcpwrappedms rarity, and fallback directives,
// then read all the match directives
fn read_probe_directives(lines: &mut Lines<BufReader<File>>) -> ProbeDirectives {
    let mut directives = ProbeDirectives::new();
    let mut lines = lines.peekable();
    loop {
        match &lines.peek() {
            None => break,
            Some(line) => {
                let line = line.as_ref().expect("failed to read line");
                if line.starts_with("Probe") {
                    break;
                } else if line.starts_with('#') || line.trim().is_empty() {
                } else if line.starts_with("match") || line.starts_with("softmatch") {
                    let (matches, soft_matches) = read_matches(&mut lines);
                    directives.matches = Some(matches);
                    directives.soft_matches = Some(soft_matches);
                    break;
                } else {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 2 {
                        break;
                    }

                    let directive = parts[0];

                    if directive == "fallback" {
                        directives.fallback =
                            Some(parts[1].split(",").map(str::to_string).collect());
                    }
                    if directive == "ports" {
                        directives.ports = Some(
                            parse_ports(parts[1])
                                .unwrap_or_else(|| panic!("failed to parse ports line")),
                        );
                    }
                    if directive == "sslports" {
                        directives.ssl_ports = Some(
                            parse_ports(parts[1])
                                .unwrap_or_else(|| panic!("failed to parse ports line")),
                        );
                    }
                    if directive == "totalwaitms" {
                        directives.total_wait_ms =
                            Some(parts[1].parse().expect("failed to parse totalwaitms"))
                    }
                    if directive == "tcpwrappedms" {
                        directives.tcp_wrapped_ms =
                            Some(parts[1].parse().expect("failed to parse tcpwrappedms"))
                    }
                    if directive == "rarity" {
                        directives.rarity = Some(parts[1].parse().expect("failed to parse rarity"))
                    }
                }
            }
        }
        lines.next();
    }

    directives
}

// Read all the matches for a given probe, stopping at the next instance of a Probe directive
fn read_matches(
    lines: &mut Peekable<&mut Lines<BufReader<File>>>,
) -> (Vec<MatchLine>, Vec<MatchLine>) {
    let mut matches = vec![];
    let mut soft_matches = vec![];
    loop {
        match &lines.peek() {
            None => break,
            Some(line) => {
                let line = line.as_ref().expect("failed to read line");
                if line.starts_with("Probe") {
                    break;
                } else {
                    if line.starts_with('#') || line.trim().is_empty() {
                    } else if line.starts_with("match") {
                        let nmap_match = parse_match_line(&line)
                            .unwrap_or_else(|| panic!("failed to parse match line {}", &line));
                        matches.push(nmap_match);
                    } else if line.starts_with("softmatch") {
                        let nmap_match = parse_match_line(&line)
                            .unwrap_or_else(|| panic!("failed to parse softmatch line {}", &line));
                        soft_matches.push(nmap_match);
                    }
                }
            }
        }
        lines.next();
    }

    (matches, soft_matches)
}

fn parse_ports(ports: &str) -> Option<Vec<u16>> {
    let mut parsed = vec![];
    for port in ports.split(",") {
        if port.contains("-") {
            let parts: Vec<&str> = port.split("-").collect();
            if parts.len() < 2 {
                return None;
            }
            let start: u16 = parts[0].parse().ok()?;
            let end: u16 = parts[1].parse().ok()?;
            for p in start..=end {
                parsed.push(p)
            }
        } else {
            let p = port.parse().ok()?;
            parsed.push(p);
        }
    }
    Some(parsed)
}
