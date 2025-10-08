use hyper::{Body, Request};
use std::collections::HashMap;
use std::string::String;

pub fn get_url_params(req: &Request<Body>) -> HashMap<String, String> {
    req.uri()
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new)
}
pub fn get_url_param<T: std::str::FromStr>(
    hashmap: &HashMap<String, String>,
    keyname: &str,
) -> Option<T> {
    match hashmap.get(&keyname.to_string()) {
        None => None,
        Some(vs) => match vs.parse::<T>() {
            Err(_) => {
                error!("Unable to parse papameter {}={}", keyname, vs);
                None
            }
            Ok(n) => Some(n),
        },
    }
}
pub fn is_multicast(a: &std::net::IpAddr) -> bool {
    match a {
        std::net::IpAddr::V4(va) => is_multicast_v4(va),
        std::net::IpAddr::V6(va) => is_multicast_v6(va),
    }
}
pub fn is_multicast_v4(a: &std::net::Ipv4Addr) -> bool {
    (a.octets() != [255, 255, 255, 255]) && (a.octets()[0] >= 224)
}
pub fn is_multicast_v6(a: &std::net::Ipv6Addr) -> bool {
    a.octets()[0] == 255
}
