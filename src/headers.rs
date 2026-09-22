//! Request header parsing for RFC 8030 (`TTL`, `Urgency`, `Topic`), RFC 7240
//! (`Prefer`), and RFC 8288 (`Link`).
//!
//! Pure functions over a [`HeaderMap`]. A header that is present but
//! malformed yields [`Invalid`], which callers answer with 400.

use std::time::{Duration, UNIX_EPOCH};

use http::HeaderMap;

use crate::store::Urgency;

/// A header that is present but malformed or repeated.
#[derive(Debug)]
pub struct Invalid;

/// TTLs past 2^31 seconds are treated as 2^31 (RFC 8030 §5.2).
const TTL_CEILING: u64 = 1 << 31;

/// The value of a header that may appear at most once.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Invalid> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Invalid);
    }
    let value = value.to_str().map_err(|_| Invalid)?;
    Ok(Some(value.trim_matches([' ', '\t'])))
}

/// `TTL = 1*DIGIT` (RFC 8030 §5.2). Required.
pub fn ttl(headers: &HeaderMap) -> Result<u64, Invalid> {
    let value = single(headers, "ttl")?.ok_or(Invalid)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Invalid);
    }
    // All digits, so the only parse failure is overflow.
    Ok(value
        .parse()
        .map_or(TTL_CEILING, |n: u64| n.min(TTL_CEILING)))
}

/// A single `Urgency` value (RFC 8030 §5.3). A comma list is not a value.
pub fn urgency(headers: &HeaderMap) -> Result<Option<Urgency>, Invalid> {
    single(headers, "urgency")?
        .map(|v| Urgency::parse(v).ok_or(Invalid))
        .transpose()
}

/// `Topic`: 1 to 32 characters of the base64url alphabet (RFC 8030 §5.4).
pub fn topic(headers: &HeaderMap) -> Result<Option<String>, Invalid> {
    let Some(value) = single(headers, "topic")? else {
        return Ok(None);
    };
    if value.is_empty() || value.len() > 32 || !value.bytes().all(is_b64url) {
        return Err(Invalid);
    }
    Ok(Some(value.to_owned()))
}

/// The `Prefer` preferences this service acts on (RFC 7240).
#[derive(Debug, Default)]
pub struct Prefer {
    /// `respond-async`: on a push, the application server wants a delivery
    /// receipt (RFC 8030 §5.1).
    pub respond_async: bool,
    /// `wait=N`, in seconds. On a receipt stream, `wait=0` asks for the
    /// receipts already queued and an immediate end of the stream.
    pub wait: Option<u64>,
}

/// The preferences this service acts on (RFC 7240). Unknown preferences and
/// their parameters are ignored.
pub fn prefer(headers: &HeaderMap) -> Prefer {
    let mut out = Prefer::default();
    for value in headers.get_all("prefer") {
        for pref in value.to_str().unwrap_or("").split(',') {
            let token = pref.split(';').next().unwrap_or("").trim();
            let (name, value) = match token.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
                None => (token, None),
            };
            if name.eq_ignore_ascii_case("respond-async") {
                out.respond_async = true;
            } else if name.eq_ignore_ascii_case("wait") {
                out.wait = value.and_then(|v| v.parse().ok());
            }
        }
    }
    out
}

/// Target of the first `Link` whose relation types include `rel` (RFC 8288).
/// Link values that do not parse are skipped.
pub fn link(headers: &HeaderMap, rel: &str) -> Option<String> {
    for value in headers.get_all("link") {
        let Ok(value) = value.to_str() else { continue };
        for link in split_outside(value, ',') {
            let Some((target, params)) = link
                .trim()
                .strip_prefix('<')
                .and_then(|l| l.split_once('>'))
            else {
                continue;
            };
            let matches = split_outside(params, ';').into_iter().any(|p| {
                p.split_once('=').is_some_and(|(name, val)| {
                    name.trim().eq_ignore_ascii_case("rel")
                        && val
                            .trim()
                            .trim_matches('"')
                            .split_ascii_whitespace()
                            .any(|r| r.eq_ignore_ascii_case(rel))
                })
            });
            if matches {
                return Some(target.to_owned());
            }
        }
    }
    None
}

/// Split on `sep`, ignoring separators inside `<...>` or quoted strings.
fn split_outside(s: &str, sep: char) -> Vec<&str> {
    let (mut parts, mut start, mut angle, mut quote) = (Vec::new(), 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            '<' if !quote => angle = true,
            '>' if !quote => angle = false,
            '"' if !angle => quote = !quote,
            c if c == sep && !angle && !quote => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// The resource id in a link target that is either `{origin}{prefix}{id}` or
/// the absolute path `{prefix}{id}`.
pub fn resource_id<'a>(target: &'a str, origin: &str, prefix: &str) -> Option<&'a str> {
    let path = target.strip_prefix(origin).unwrap_or(target);
    path.strip_prefix(prefix).filter(|id| is_id(id))
}

/// Whether `b` is in the base64url alphabet (RFC 4648 §5).
fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Shape of every id this service issues: 16 random octets, base64url.
pub fn is_id(s: &str) -> bool {
    s.len() == 22 && s.bytes().all(is_b64url)
}

/// Format a Unix timestamp in milliseconds as an HTTP-date (RFC 9110 §5.6.7).
pub fn http_date(unix_ms: u64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(unix_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header map with every pair appended, repeats included.
    fn map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn ttl_grammar() {
        assert_eq!(ttl(&map(&[("ttl", "60")])).unwrap(), 60);
        assert_eq!(
            ttl(&map(&[("ttl", "99999999999999999999")])).unwrap(),
            1 << 31
        );
        for bad in ["", "-1", "1.5", "10, 20", "abc"] {
            assert!(ttl(&map(&[("ttl", bad)])).is_err(), "{bad:?}");
        }
        assert!(ttl(&map(&[("ttl", "1"), ("ttl", "2")])).is_err());
        assert!(ttl(&HeaderMap::new()).is_err());
    }

    #[test]
    fn prefer_list() {
        let p = prefer(&map(&[("prefer", "wait=5, respond-async")]));
        assert!(p.respond_async);
        assert_eq!(p.wait, Some(5));
        assert_eq!(prefer(&map(&[("prefer", "wait=0")])).wait, Some(0));
    }

    #[test]
    fn link_rel_matching() {
        let h = map(&[(
            "link",
            "<https://a/x>; rel=\"other\", </subscription-set/y>; rel=\"urn:ietf:params:push:set\"",
        )]);
        assert_eq!(
            link(&h, "urn:ietf:params:push:set").as_deref(),
            Some("/subscription-set/y")
        );
        assert_eq!(link(&h, "urn:ietf:params:push"), None);
    }

    #[test]
    fn resource_ids() {
        let id = "AAAAAAAAAAAAAAAAAAAAAA";
        let abs = format!("https://h/push/{id}");
        assert_eq!(resource_id(&abs, "https://h", "/push/"), Some(id));
        assert_eq!(
            resource_id(&format!("/push/{id}"), "https://h", "/push/"),
            Some(id)
        );
        assert_eq!(resource_id("/push/short", "https://h", "/push/"), None);
        assert_eq!(
            resource_id(&format!("https://evil/push/{id}"), "https://h", "/push/"),
            None
        );
    }
}
