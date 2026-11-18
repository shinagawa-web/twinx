//! Choosing the location for a URI, as ngx_http_core_find_location does:
//! exact match, longest prefix (with nested locations), `^~`, then regular
//! expressions in configuration order.

use std::sync::Arc;

use crate::config::{Location, Modifier};

pub type Captures = Vec<Option<String>>;

#[derive(Debug, Clone)]
pub enum Found {
    /// A location was chosen; regex captures, if any.
    Location(Arc<Location>, Captures),
    /// The URI names a proxied prefix location without its trailing slash:
    /// answer with a redirect to the location name.
    AutoRedirect(Arc<Location>),
    /// No location matches; the server-level configuration applies.
    None,
}

enum Outcome {
    Final(Arc<Location>, Captures),
    Redirect(Arc<Location>),
    Prefix(Option<Arc<Location>>),
}

pub fn find(locations: &[Arc<Location>], uri: &str) -> Found {
    match find_in(locations, uri) {
        Outcome::Final(l, c) => Found::Location(l, c),
        Outcome::Redirect(l) => Found::AutoRedirect(l),
        Outcome::Prefix(Some(l)) => Found::Location(l, Vec::new()),
        Outcome::Prefix(None) => Found::None,
    }
}

fn is_prefix(m: Modifier) -> bool {
    matches!(m, Modifier::Prefix | Modifier::NoRegex)
}

fn find_in(locations: &[Arc<Location>], uri: &str) -> Outcome {
    if let Some(l) = locations.iter().find(|l| l.modifier == Modifier::Exact && l.name == uri) {
        return Outcome::Final(l.clone(), Vec::new());
    }
    if let Some(l) = locations.iter().find(|l| {
        (is_prefix(l.modifier) || l.modifier == Modifier::Exact)
            && l.conf.auto_redirect
            && l.name.len() == uri.len() + 1
            && l.name.starts_with(uri)
    }) {
        return Outcome::Redirect(l.clone());
    }
    let best = locations
        .iter()
        .filter(|l| is_prefix(l.modifier) && uri.starts_with(l.name.as_str()))
        .max_by_key(|l| l.name.len())
        .cloned();
    let mut current = best.clone();
    if let Some(b) = &best {
        if !b.children.is_empty() {
            match find_in(&b.children, uri) {
                Outcome::Prefix(Some(inner)) => current = Some(inner),
                Outcome::Prefix(None) => {}
                other => return other,
            }
        }
        if b.modifier == Modifier::NoRegex {
            return Outcome::Final(current.unwrap_or_else(|| b.clone()), Vec::new());
        }
    }
    for l in locations {
        let Some(re) = &l.regex else { continue };
        if let Some(caps) = re.captures(uri) {
            let captures: Captures = caps.iter().map(|m| m.map(|m| m.as_str().to_string())).collect();
            if !l.children.is_empty() {
                match find_in(&l.children, uri) {
                    Outcome::Prefix(Some(inner)) => return Outcome::Final(inner, captures),
                    Outcome::Prefix(None) => {}
                    other => return other,
                }
            }
            return Outcome::Final(l.clone(), captures);
        }
    }
    Outcome::Prefix(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn locations(server: &str) -> Vec<Arc<Location>> {
        let text = format!("events {{}} http {{ server {{ {server} }} }}");
        let tree = config::parse_text(&text, "t", std::path::Path::new("/")).unwrap();
        let c = config::build(&tree).unwrap();
        c.servers[0].locations.clone()
    }

    fn name(found: Found) -> String {
        match found {
            Found::Location(l, _) => l.name.clone(),
            Found::AutoRedirect(l) => format!("redirect {}", l.name),
            Found::None => "none".into(),
        }
    }

    #[test]
    fn follows_nginx_precedence() {
        let l = locations(
            "location / {} location = / {} location /images/ {} location ^~ /static/ {}
             location ~* \\.(gif|jpg)$ {} location /docs/ { location ~ \\.txt$ {} }",
        );
        assert_eq!(name(find(&l, "/")), "/");
        assert_eq!(name(find(&l, "/index.html")), "/");
        assert_eq!(name(find(&l, "/images/a.gif")), "\\.(gif|jpg)$");
        assert_eq!(name(find(&l, "/images/a.png")), "/images/");
        assert_eq!(name(find(&l, "/static/a.JPG")), "/static/");
        assert_eq!(name(find(&l, "/docs/a.txt")), "\\.txt$");
        assert_eq!(name(find(&l, "/docs/a.gif")), "\\.(gif|jpg)$");
    }

    #[test]
    fn redirects_to_proxied_locations_with_a_slash() {
        let l = locations("location /api/ { proxy_pass http://127.0.0.1:1; } location /x/ {}");
        assert_eq!(name(find(&l, "/api")), "redirect /api/");
        assert_eq!(name(find(&l, "/x")), "none");
    }

    #[test]
    fn captures_regex_groups() {
        let l = locations("location ~ ^/u/(\\w+)$ {}");
        match find(&l, "/u/bob") {
            Found::Location(_, c) => assert_eq!(c[1].as_deref(), Some("bob")),
            _ => panic!(),
        }
    }
}
