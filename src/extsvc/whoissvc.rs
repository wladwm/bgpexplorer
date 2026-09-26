use super::{StoreKey, StoreVal};
use crate::config::SvcConfig;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use whois_rust::{WhoIs, WhoIsLookupOptions, WhoIsServerValue};

pub struct WhoisSvr {
    whs: WhoIs,
    req_timeout: std::time::Duration,
    cache_valid: chrono::Duration,
    db: Arc<sled::Db>,
}

impl WhoisSvr {
    pub fn new(conf: &SvcConfig, db: Arc<sled::Db>) -> WhoisSvr {
        WhoisSvr {
            whs: conf.whois.config.clone(),
            req_timeout: conf.whois.timeout.into(),
            cache_valid: conf.cache_valid.into(),
            db,
        }
    }
    pub async fn do_query_whois(
        self: &Arc<WhoisSvr>,
        target: String,
        checkitem: Option<&'static Regex>,
        filterstr: Option<&str>,
    ) -> anyhow::Result<String> {
        lazy_static! {
            static ref RE_WHOIS: Regex = Regex::new(r"\b(whois\.[\.a-z0-9\-]+)\b").unwrap();
        }
        let lkey: sled::IVec = StoreKey::whois_query(target.clone()).into();
        let mut deep: usize = 16;
        let mut whoises: HashMap<String, bool> = HashMap::new();
        while deep > 0 {
            deep -= 1;
            let mut opts = WhoIsLookupOptions::from_string(target.clone())?;
            opts.timeout = Some(self.req_timeout);
            if !whoises.is_empty() {
                loop {
                    let whfnd = match whoises.iter().find(|x| *x.1) {
                        None => return Ok(String::from("")),
                        Some(v) => v.0.clone(),
                    };
                    if !whfnd.is_empty() {
                        whoises.insert(whfnd.clone(), false);
                        opts.server = Some(match WhoIsServerValue::from_string(whfnd) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Invalid whois server: {:?}", e);
                                continue;
                            }
                        });
                    };
                    break;
                }
            }
            let res = self.whs.lookup_async(opts).await?;
            match checkitem {
                None => {
                    self.db.insert(lkey, StoreVal::new(res.clone())).unwrap();
                    return Ok(Self::process_response(res, checkitem, filterstr));
                }
                Some(_) => {
                    let v = Self::findstr(res.as_str(), checkitem);
                    if !v.is_empty() {
                        self.db.insert(lkey, StoreVal::new(res.clone()))?;
                        return Ok(Self::process_response(res, checkitem, filterstr));
                    };
                }
            };
            for i in RE_WHOIS.find_iter(res.as_str()) {
                let whoissvr = i.as_str();
                if !whoises.contains_key(whoissvr) {
                    whoises.insert(whoissvr.to_string(), true);
                };
            }
            if whoises.is_empty() {
                return Ok(Self::process_response(res, checkitem, filterstr));
            };
        }
        Err(anyhow!("Search failed"))
    }
    pub async fn query_whois(
        self: &Arc<WhoisSvr>,
        target: String,
        checkitem: Option<&'static Regex>,
        filterstr: Option<&str>,
    ) -> anyhow::Result<String> {
        let lkey: sled::IVec = StoreKey::whois_query(target.clone()).into();
        match self.db.get(lkey.clone()) {
            Ok(r) => {
                if let Some(v) = r {
                    if v.len() > 0 {
                        match serde_json::from_slice::<StoreVal>(&v) {
                            Ok(q) => {
                                if chrono::Local::now().signed_duration_since(q.modified())
                                    > self.cache_valid
                                {
                                    let slf = self.clone();
                                    tokio::spawn(async move {
                                        slf.do_query_whois(target, checkitem, None).await
                                    });
                                }
                                return Ok(q.val);
                            }
                            Err(e) => {
                                warn!("Deserialize error: {:?}", e);
                            }
                        };
                    };
                };
            }
            Err(e) => warn!("sled error: {:?}", e),
        };
        self.do_query_whois(target, checkitem, filterstr).await
    }
    fn filterout_comments(s: &str) -> Vec<&str> {
        s.split('\n')
            .filter(|q| {
                if !q.is_empty() {
                    if let Some(fc) = q.chars().next() {
                        return fc != '%';
                    }
                };
                false
            })
            .collect()
    }
    fn findstr<'a>(s: &'a str, tofind: Option<&Regex>) -> Vec<&'a str> {
        match tofind {
            None => Self::filterout_comments(s),
            Some(fnd) => s
                .split('\n')
                .filter(|q| {
                    if !q.is_empty() {
                        if let Some(fc) = q.chars().next() {
                            return fc != '%' && fc != '#';
                        }
                    };
                    false
                })
                .skip_while(|x| !fnd.is_match(x))
                .collect(),
        }
    }
    fn process_response(rsp: String, checkitem: Option<&Regex>, filterstr: Option<&str>) -> String {
        if checkitem.is_none() && filterstr == Some("raw") {
            return rsp;
        }
        let v = Self::findstr(rsp.as_str(), checkitem);
        if !v.is_empty() {
            v.join("\n")
        } else {
            Self::filterout_comments(rsp.as_str()).join("\n")
        }
    }
}
