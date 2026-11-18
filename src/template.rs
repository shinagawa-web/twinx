//! Values with variables ("complex values" in nginx): `$uri`, `${host}`,
//! `$1` for regex captures, and literal text around them.

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Lit(String),
    Var(String),
    Capture(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    pub raw: String,
    pub parts: Vec<Part>,
}

/// Supplies variable values when a template is evaluated.
pub trait Vars {
    fn var(&self, name: &str) -> Option<String>;
    fn capture(&self, index: usize) -> Option<String>;
}

const KNOWN: &[&str] = &[
    "args",
    "query_string",
    "is_args",
    "uri",
    "document_uri",
    "request_uri",
    "request",
    "request_method",
    "request_filename",
    "host",
    "hostname",
    "scheme",
    "https",
    "server_name",
    "server_port",
    "server_addr",
    "server_protocol",
    "remote_addr",
    "remote_port",
    "document_root",
    "realpath_root",
    "content_length",
    "content_type",
    "nginx_version",
    "proxy_host",
    "proxy_port",
    "proxy_add_x_forwarded_for",
    "status",
    "msec",
    "time_local",
    "time_iso8601",
    "request_length",
    "connection",
    "pid",
];

const PREFIXES: &[&str] = &["http_", "arg_", "cookie_", "sent_http_", "upstream_http_"];

pub fn known_variable(name: &str) -> bool {
    KNOWN.contains(&name)
        || PREFIXES
            .iter()
            .any(|p| name.len() > p.len() && name.starts_with(p))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

impl Template {
    pub fn literal(s: &str) -> Template {
        Template { raw: s.to_string(), parts: vec![Part::Lit(s.to_string())] }
    }

    /// Parses a value; unknown variables are refused as nginx refuses them.
    pub fn parse(s: &str) -> Result<Template, String> {
        let chars: Vec<char> = s.chars().collect();
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c != '$' {
                lit.push(c);
                i += 1;
                continue;
            }
            i += 1;
            if i < chars.len() && chars[i].is_ascii_digit() {
                if !lit.is_empty() {
                    parts.push(Part::Lit(std::mem::take(&mut lit)));
                }
                parts.push(Part::Capture(chars[i] as usize - '0' as usize));
                i += 1;
                continue;
            }
            let braced = i < chars.len() && chars[i] == '{';
            if braced {
                i += 1;
            }
            let start = i;
            while i < chars.len() && is_name_char(chars[i]) {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            if braced {
                if i >= chars.len() || chars[i] != '}' {
                    return Err("the closing bracket in \"".to_string()
                        + &name
                        + "\" variable is missing");
                }
                i += 1;
            }
            if name.is_empty() {
                return Err("invalid variable name in \"".to_string() + s + "\"");
            }
            if !known_variable(&name) {
                return Err(format!("unknown \"{name}\" variable"));
            }
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(&mut lit)));
            }
            parts.push(Part::Var(name));
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        Ok(Template { raw: s.to_string(), parts })
    }

    pub fn is_static(&self) -> bool {
        self.parts.iter().all(|p| matches!(p, Part::Lit(_)))
    }

    pub fn has_captures(&self) -> bool {
        self.parts.iter().any(|p| matches!(p, Part::Capture(_)))
    }

    pub fn eval(&self, vars: &dyn Vars) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Lit(s) => out.push_str(s),
                Part::Var(name) => out.push_str(&vars.var(name).unwrap_or_default()),
                Part::Capture(n) => out.push_str(&vars.capture(*n).unwrap_or_default()),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl Vars for Fixed {
        fn var(&self, name: &str) -> Option<String> {
            match name {
                "uri" => Some("/a/b".into()),
                "host" => Some("example.test".into()),
                _ => None,
            }
        }
        fn capture(&self, index: usize) -> Option<String> {
            (index == 1).then(|| "cap".to_string())
        }
    }

    #[test]
    fn evaluates_variables_and_captures() {
        let t = Template::parse("$uri/ ${host}x $1-$2").unwrap();
        assert_eq!(t.eval(&Fixed), "/a/b/ example.testx cap-");
        assert!(!t.is_static());
        assert!(Template::parse("plain").unwrap().is_static());
    }

    #[test]
    fn refuses_unknown_variables() {
        assert_eq!(Template::parse("$nope").unwrap_err(), "unknown \"nope\" variable");
        assert!(Template::parse("$http_user_agent").is_ok());
        assert!(Template::parse("${uri").is_err());
    }
}
