pub fn unescape(s: String) -> Vec<u8> {
    let mut chars: Vec<char> = s.chars().into_iter().rev().collect();
    let mut unescaped = vec![];

    while let Some(c) = chars.pop() {
        if c != '\\' {
            unescaped.push(c.as_ascii().unwrap().to_u8());

            continue;
        }

        let c = chars.pop().unwrap();
        let c = match c {
            '0' => '\0'.as_ascii().unwrap().to_u8(),
            'n' => '\n'.as_ascii().unwrap().to_u8(),
            'r' => '\r'.as_ascii().unwrap().to_u8(),
            't' => '\t'.as_ascii().unwrap().to_u8(),
            '\'' | '\"' | '\\' | '/' => c.as_ascii().unwrap().to_u8(),
            'x' => {
                let mut byte = String::new();

                for i in 0..2 {
                    let c = chars.pop().unwrap();

                    byte.push(c);
                }
                u8::from_str_radix(&byte, 16).unwrap()
            }
            _ => c.as_ascii().unwrap().to_u8(),
        };

        unescaped.push(c);
    }

    unescaped
}
