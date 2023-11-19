use pcre2::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
pub mod parse;

#[derive(Clone, Debug, Serialize)]
pub struct ServiceProbe {
    pub probe: Probe,
    pub directives: ProbeDirectives,
}
impl ServiceProbe {
    pub fn check_match(&self, response: &str) -> Option<Match> {
        let empty: Vec<Match> = vec![];
        let matches = self.directives.matches.as_ref().unwrap_or(&empty);
        let soft_matches = self.directives.soft_matches.as_ref().unwrap_or(&empty);
        for service_match in matches {
            let service_match_result = get_match(&service_match, response);
            if service_match_result.is_some() {
                return service_match_result;
            }
        }
        for service_match in soft_matches {
            let service_match_result = get_match(&service_match, response);
            if service_match_result.is_some() {
                return service_match_result;
            }
        }

        None
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceProbes {
    pub tcp_probes: Vec<ServiceProbe>,
    pub udp_probes: Vec<ServiceProbe>,
}

impl ServiceProbes {
    fn new() -> Self {
        Self {
            tcp_probes: vec![],
            udp_probes: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
pub struct Match {
    pub service: String,
    pub pattern: String,
    #[serde(skip_serializing)]
    pub re: Regex,
    pub pattern_options: String,
    pub version_info: String,
}

// if the regex in the service_match matches the response,
// return a new Match with the version_info field replaced by the capture groups
pub fn get_match(service_match: &Match, response: &str) -> Option<Match> {
    if !service_match
        .re
        .is_match(response.as_bytes())
        .unwrap_or_else(|e| {
            panic!(
                "failed to run regex {} on response {} with error {}",
                service_match.pattern,
                response,
                e.to_string()
            )
        })
    {
        return None;
    }

    /*
    let version_info = service_match
        .re
        .replace(response, &service_match.version_info);
    */
    Some(Match {
        ..service_match.clone()
    })
}
