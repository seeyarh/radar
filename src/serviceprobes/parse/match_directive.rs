use crate::serviceprobes::Match;
use pcre2::bytes::RegexBuilder;

pub fn parse_match_line(line: &str) -> Option<Match> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 || (parts[0] != "match" && parts[0] != "softmatch") {
        return None;
    }

    let service = parts[1].to_string();

    // Identifying the pattern delimiter and start of the pattern
    let delimiter = parts[2].chars().nth(1)?;
    let pattern_version_info = parts[2..].join(" ");
    let pattern_start_index = pattern_version_info.find(delimiter)? + 1;
    let remainder = &pattern_version_info[pattern_start_index..];

    // Finding the end of the pattern
    let pattern_end_index = remainder.find(delimiter)?;
    let pattern = &remainder[..pattern_end_index];

    // Extract pattern options and version info, if present
    let mut pattern_options = "";
    let mut version_info = "";
    if remainder.len() > pattern_end_index + 1 {
        if !remainder
            .chars()
            .nth(pattern_end_index + 1)
            .unwrap()
            .is_whitespace()
        {
            let parts: Vec<&str> = remainder[pattern_end_index + 1..]
                .split_whitespace()
                .collect();
            pattern_options = parts[0]
        }

        version_info = remainder[pattern_end_index + pattern_options.len() + 1..].trim();
    }

    let re = RegexBuilder::new()
        .caseless(pattern_options.contains("i"))
        .dotall(pattern_options.contains("s"))
        .build(&pattern)
        .unwrap_or_else(|e| {
            panic!(
                "failed to create regex for match line {} with error {}",
                line,
                e.to_string()
            )
        });

    Some(Match {
        service,
        pattern: pattern.into(),
        re,
        pattern_options: pattern_options.into(),
        version_info: version_info.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_match_line() {
        let line = "match ftp m/^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/";
        let result = parse_match_line(line);

        assert!(result.is_some());
        let parsed_match = result.unwrap();

        assert_eq!(parsed_match.service, "ftp");
        assert_eq!(
            parsed_match.pattern,
            "^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)"
        );
        assert_eq!(parsed_match.pattern_options, "");
        assert_eq!(
            parsed_match.version_info,
            "p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/"
        );

        let example_response = "220 Welcome to Pure-FTPd 1.0.24";
        let captures = parsed_match
            .re
            .captures(example_response.as_bytes())
            .expect("error running regex")
            .expect("no captues");
        captures.get(1).expect("no group");
    }

    #[test]
    fn test_parse_match_line_with_pattern_options() {
        let line = r#"match http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Askey Software ([\d.]+)\r\n.*<title>Scientific.A..anta WebStar Cable Modem</title>.*|si p/Scientific Atlanta WebStar cable modem http config/ i/Askey Software $1/ d/broadband router/"#;
        let result = parse_match_line(line);

        assert!(result.is_some());
        let parsed_line = result.unwrap();

        assert_eq!(parsed_line.service, "http");
        assert_eq!(
            parsed_line.pattern,
            r#"^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Askey Software ([\d.]+)\r\n.*<title>Scientific.A..anta WebStar Cable Modem</title>.*"#,
        );
        assert_eq!(parsed_line.pattern_options, "si");
        assert_eq!(
            parsed_line.version_info,
            r#"p/Scientific Atlanta WebStar cable modem http config/ i/Askey Software $1/ d/broadband router/"#,
        );
    }

    #[test]
    fn test_parse_match_line_with_no_version_info() {
        let line = r#"match sharp-remote m|^(?!x)x|"#;
        let result = parse_match_line(line);

        assert!(result.is_some());
        let parsed_line = result.unwrap();

        assert_eq!(parsed_line.service, "sharp-remote");
        assert_eq!(parsed_line.pattern, r#"^(?!x)x"#,);
        assert_eq!(parsed_line.pattern_options, "");
        assert_eq!(parsed_line.version_info, "");
    }
}
