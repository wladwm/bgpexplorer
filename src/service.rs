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
            Err(_) => None,
            Ok(n) => Some(n),
        },
    }
}
