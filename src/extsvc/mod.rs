use crate::*;
use chrono::prelude::*;
#[cfg(feature = "whoisreq")]
use regex::Regex;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use std::sync::Arc;

#[cfg(feature = "dnsreq")]
pub mod dnssvc;
#[cfg(feature = "whoisreq")]
pub mod whoissvc;

const CONTENT_TYPE: &str = "Content-Type";
const TEXT_PLAIN: &str = "text/plain";

pub struct ExtSvr {
    #[cfg(feature = "whoisreq")]
    pub whois: Arc<whoissvc::WhoisSvr>,
    #[cfg(feature = "dnsreq")]
    pub dns: Arc<dnssvc::DnsSvr>,
}

impl ExtSvr {
    pub fn new(conf: &SvcConfig) -> anyhow::Result<ExtSvr> {
        let db = Arc::new(
            sled::Config::default()
                .flush_every_ms(Some(10000))
                .path(conf.cachedb.clone())
                .open()?,
        );
        #[cfg(feature = "whoisreq")]
        let whois = Arc::new(whoissvc::WhoisSvr::new(conf, db.clone()));
        #[cfg(feature = "dnsreq")]
        let dns = Arc::new(dnssvc::DnsSvr::new(conf, db.clone()));
        Ok(ExtSvr {
            #[cfg(feature = "whoisreq")]
            whois,
            #[cfg(feature = "dnsreq")]
            dns,
        })
    }
    pub async fn response_fn(
        self: &Arc<ExtSvr>,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        //Ok(not_found())
        match self.handle_query(req).await {
            Ok(v) => Ok(v),
            Err(e) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, TEXT_PLAIN)
                .body(format!("{:?}", e).into())
                .unwrap()),
        }
    }
    pub fn invalid_query() -> Response<Body> {
        Response::builder()
            .status(StatusCode::from_u16(500).unwrap())
            .header(CONTENT_TYPE, TEXT_PLAIN)
            .body(b"Invalid request"[..].into())
            .unwrap()
    }
    pub async fn handle_query(
        self: &Arc<ExtSvr>,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let requri = req.uri().path();
        let urlparts: Vec<&str> = requri.split('/').collect();
        if urlparts.len() < 3 {
            return Ok(not_found());
        }
        #[cfg(feature = "dnsreq")]
        if urlparts.len() > 3 && urlparts[1] == "api" && urlparts[2] == "dns" {
            let rsp = match self.dns.query_dns_ptr(urlparts[3].to_string()).await {
                Ok(v) => v,
                Err(e) => {
                    return Response::builder()
                        .status(StatusCode::from_u16(500).unwrap())
                        .header(CONTENT_TYPE, TEXT_PLAIN)
                        .body(format!("Error: {:?}", e).into());
                }
            };
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, TEXT_PLAIN)
                .body(rsp.into());
        }
        #[cfg(feature = "whoisreq")]
        if urlparts.len() > 3 && urlparts[1] == "api" && urlparts[2] == "whois" {
            let params = crate::service::get_url_params(req);
            let query = match crate::service::get_url_param::<String>(&params, "query") {
                Some(s) => s,
                None => {
                    return Ok(Self::invalid_query());
                }
            };
            if query.is_empty() {
                return Ok(Self::invalid_query());
            };
            lazy_static! {
                static ref RE_AS: Regex = Regex::new(r"(aut-num|ASNumber):").unwrap();
                static ref RE_ROUTE: Regex = Regex::new(r"route:").unwrap();
                static ref RE_ROUTE6: Regex = Regex::new(r"route6:").unwrap();
            }
            let checkstr: Option<&'static Regex> = if urlparts.len() >= 4 {
                match urlparts[3] {
                    "aut-num" | "as" => Some(&RE_AS),
                    "r" | "r4" | "route" => Some(&RE_ROUTE),
                    "r6" | "route6" => Some(&RE_ROUTE6),
                    _ => None,
                }
            } else {
                None
            };
            let rsp = match self
                .whois
                .query_whois(
                    query,
                    checkstr.clone(),
                    if urlparts.len() >= 4 {
                        Some(urlparts[3])
                    } else {
                        None
                    },
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return Response::builder()
                        .status(StatusCode::from_u16(500).unwrap())
                        .header(CONTENT_TYPE, TEXT_PLAIN)
                        .body(format!("Error: {:?}", e).into());
                }
            };
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, TEXT_PLAIN)
                .body(rsp.into());
        };
        Ok(not_found())
    }
}

#[derive(Debug)]
enum StoreKey {
    #[cfg(feature = "whoisreq")]
    Whois(String),
    #[cfg(feature = "dnsreq")]
    Dns(String),
}
impl StoreKey {
    #[cfg(feature = "whoisreq")]
    fn whois_query(s: String) -> StoreKey {
        StoreKey::Whois(s)
    }
    #[cfg(feature = "dnsreq")]
    fn dns_query(s: String) -> StoreKey {
        StoreKey::Dns(s)
    }
}
impl serde::Serialize for StoreKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WK", 1)?;
        match self {
            #[cfg(feature = "whoisreq")]
            StoreKey::Whois(s) => {
                state.serialize_field("whois", s)?;
            }
            #[cfg(feature = "dnsreq")]
            StoreKey::Dns(s) => {
                state.serialize_field("dns", s)?;
            }
        }
        state.end()
    }
}
impl From<StoreKey> for sled::IVec {
    fn from(sv: StoreKey) -> sled::IVec {
        serde_json::to_vec(&sv).unwrap().into()
    }
}
#[derive(Debug)]
struct StoreVal {
    ts: DateTime<Local>,
    val: String,
}
impl StoreVal {
    fn new(vl: String) -> StoreVal {
        StoreVal {
            ts: chrono::Local::now(),
            val: vl,
        }
    }
    fn mkfrom(gts: i64, vl: String) -> StoreVal {
        lazy_static! {
            static ref GMT_OFFSET: FixedOffset = chrono::FixedOffset::east_opt(0).unwrap();
            static ref DEF_NDT: NaiveDateTime = NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
                NaiveTime::from_hms_milli_opt(12, 0, 0, 0).unwrap()
            );
        };
        StoreVal {
            ts: DateTime::from_timestamp(gts, 0)
                .map(|x| x.into())
                .unwrap_or_else(|| Local::now()),
            val: vl,
        }
    }
    fn modified(&self) -> DateTime<Local> {
        self.ts
    }
}
impl From<String> for StoreVal {
    fn from(s: String) -> StoreVal {
        StoreVal {
            ts: chrono::Local::now(),
            val: s,
        }
    }
}
impl serde::Serialize for StoreVal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WR", 2)?;
        state.serialize_field("ts", &self.ts.timestamp())?;
        state.serialize_field("val", &self.val)?;
        state.end()
    }
}
impl<'de> Deserialize<'de> for StoreVal {
    fn deserialize<D>(deserializer: D) -> Result<StoreVal, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["ts", "val"];

        enum Field {
            Ts,
            Val,
        }

        // This part could also be generated independently by:
        //
        //    #[derive(Deserialize)]
        //    #[serde(field_identifier, rename_all = "lowercase")]
        //    enum Field { Secs, Nanos }
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("`ts` or `val`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "ts" => Ok(Field::Ts),
                            "val" => Ok(Field::Val),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct StoreValVisitor;

        impl<'de> Visitor<'de> for StoreValVisitor {
            type Value = StoreVal;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct StoreKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<StoreVal, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let gts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let gval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(StoreVal::mkfrom(gts, gval))
            }

            fn visit_map<V>(self, mut map: V) -> Result<StoreVal, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut ts = None;
                let mut val = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Ts => {
                            if ts.is_some() {
                                return Err(serde::de::Error::duplicate_field("ts"));
                            }
                            ts = Some(map.next_value()?);
                        }
                        Field::Val => {
                            if val.is_some() {
                                return Err(serde::de::Error::duplicate_field("val"));
                            }
                            val = Some(map.next_value()?);
                        }
                    }
                }
                let ts = ts.ok_or_else(|| serde::de::Error::missing_field("ts"))?;
                let val = val.ok_or_else(|| serde::de::Error::missing_field("val"))?;
                Ok(StoreVal::mkfrom(ts, val))
            }
        }
        deserializer.deserialize_struct("WR", FIELDS, StoreValVisitor)
    }
}
impl From<sled::IVec> for StoreVal {
    fn from(sv: sled::IVec) -> StoreVal {
        serde_json::from_slice(&sv).unwrap()
    }
}
impl From<StoreVal> for sled::IVec {
    fn from(sv: StoreVal) -> sled::IVec {
        serde_json::to_vec(&sv).unwrap().into()
    }
}
