use crate::serviceprobes::{Probe, TransportProtocol};
use std::str::FromStr;
use unescaper::unescape;

pub fn parse_probe_line(line: &str) -> Option<Probe> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "Probe" {
        return None;
    }

    let transport_protocol = TransportProtocol::from_str(parts[1]).ok()?;
    let name = parts[2].to_string();
    let delimiter = parts[3].chars().nth(1)?;
    let probe = parts[3..].join(" ");
    let probe_start_index = probe.find(delimiter)? + 1;
    let remainder = &probe[probe_start_index..];
    let probe_end_index = remainder.find(delimiter)?;
    let probe = &remainder[..probe_end_index];
    let probe = unescape(probe).unwrap();
    let probe = probe.as_bytes();
    let mut no_payload = false;

    if remainder.len() > probe_end_index + 1 {
        let parts: Vec<&str> = remainder[probe_end_index + 1..]
            .split_whitespace()
            .collect();
        if parts[0] == "no-payload" {
            no_payload = true;
        }
    }

    Some(Probe {
        transport_protocol,
        name,
        data: probe.into(),
        no_payload,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_probe_line_null_probe() {
        let line = r#"Probe TCP NULL q||"#;
        let result = parse_probe_line(line);
        assert!(result.is_some());
        let parsed_line = result.unwrap();

        assert_eq!(parsed_line.transport_protocol, TransportProtocol::TCP);
        assert_eq!(parsed_line.data, "".as_bytes());
        assert_eq!(parsed_line.no_payload, false);
    }

    #[test]
    fn test_parse_probe_line() {
        let line = r#"Probe TCP GenericLines q|\r\n\r\n|"#;
        let result = parse_probe_line(line);
        assert!(result.is_some());
        let parsed_line = result.unwrap();

        assert_eq!(parsed_line.transport_protocol, TransportProtocol::TCP);
        assert_eq!(parsed_line.data, ("\r\n\r\n").as_bytes());
        assert_eq!(parsed_line.no_payload, false);
    }

    #[test]
    fn test_parse_probe_line_no_payload() {
        let line = r#"Probe UDP Sqlping q|\x02| no-payload"#;
        let result = parse_probe_line(line);
        assert!(result.is_some());
        let parsed_line = result.unwrap();

        assert_eq!(parsed_line.transport_protocol, TransportProtocol::UDP);
        assert_eq!(parsed_line.data, ("\x02").as_bytes());
        assert_eq!(parsed_line.no_payload, true);
    }
}
