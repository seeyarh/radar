use serde::{Deserialize, Serialize};
use std::str::FromStr;
pub mod parse;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ServiceProbe {
    probe: Probe,
    directives: ProbeDirectives,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ServiceProbes {
    pub tcp_probes: Vec<ServiceProbe>,
    pub udp_probes: Vec<ServiceProbe>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ProbeDirectives {
    matches: Option<Vec<Match>>,
    soft_matches: Option<Vec<Match>>,
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
pub enum TransportProtocol {
    TCP,
    UDP,
}

impl FromStr for TransportProtocol {
    type Err = ();

    fn from_str(input: &str) -> Result<TransportProtocol, Self::Err> {
        match input {
            "TCP" => Ok(TransportProtocol::TCP),
            "UDP" => Ok(TransportProtocol::UDP),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Probe {
    pub transport_protocol: TransportProtocol,
    pub name: String,
    pub data: String,
    pub no_payload: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Match {
    service: String,
    pattern: String,
    pattern_options: String,
    version_info: String,
}

impl ServiceProbes {
    fn new() -> Self {
        Self {
            tcp_probes: vec![],
            udp_probes: vec![],
        }
    }
}
