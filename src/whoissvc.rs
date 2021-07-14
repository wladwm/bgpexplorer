use crate::*;
use crate::config::*;
use chrono::prelude::*;
use dnssector::*;
use regex::Regex;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use std::collections::HashMap;
use whois_rust::{WhoIs, WhoIsError, WhoIsLookupOptions, WhoIsServerValue};

#[derive(Debug)]
enum WhoisKey {
    ExtWhois(String),
    DNS(String),
}
impl WhoisKey {
    fn whois_query(s: String) -> WhoisKey {
        WhoisKey::ExtWhois(s)
    }
    fn dns_query(s: String) -> WhoisKey {
        WhoisKey::DNS(s)
    }
}
impl serde::Serialize for WhoisKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WK", 1)?;
        match self {
            WhoisKey::ExtWhois(s) => {
                state.serialize_field("whois", s)?;
            }
            WhoisKey::DNS(s) => {
                state.serialize_field("dns", s)?;
            }
        }
        state.end()
    }
}
impl From<WhoisKey> for sled::IVec {
    fn from(sv: WhoisKey) -> sled::IVec {
        serde_json::to_vec(&sv).unwrap().into()
    }
}
#[derive(Debug)]
struct WhoisRec {
    ts: DateTime<Local>,
    val: String,
}
impl WhoisRec {
    fn new(vl: String) -> WhoisRec {
        WhoisRec {
            ts: chrono::Local::now(),
            val: vl,
        }
    }
    fn mkfrom(gts: i64, vl: String) -> WhoisRec {
        WhoisRec {
            ts: DateTime::<Local>::from_utc(
                NaiveDateTime::from_timestamp(gts, 0),
                chrono::FixedOffset::east(0),
            ),
            val: vl,
        }
    }
    fn modified(&self) -> DateTime<Local> {
        self.ts
    }
}
impl From<String> for WhoisRec {
    fn from(s: String) -> WhoisRec {
        WhoisRec {
            ts: chrono::Local::now(),
            val: s,
        }
    }
}
impl serde::Serialize for WhoisRec {
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
impl<'de> Deserialize<'de> for WhoisRec {
    fn deserialize<D>(deserializer: D) -> Result<WhoisRec, D::Error>
    where
        D: Deserializer<'de>,
    {
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

        struct WhoisRecVisitor;

        impl<'de> Visitor<'de> for WhoisRecVisitor {
            type Value = WhoisRec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct WhoisRec")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<WhoisRec, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let gts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let gval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(WhoisRec::mkfrom(gts, gval))
            }

            fn visit_map<V>(self, mut map: V) -> Result<WhoisRec, V::Error>
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
                Ok(WhoisRec::mkfrom(ts, val))
            }
        }

        const FIELDS: &'static [&'static str] = &["ts", "val"];
        deserializer.deserialize_struct("WR", FIELDS, WhoisRecVisitor)
    }
}
impl From<sled::IVec> for WhoisRec {
    fn from(sv: sled::IVec) -> WhoisRec {
        serde_json::from_slice(&sv).unwrap()
    }
}
impl From<WhoisRec> for sled::IVec {
    fn from(sv: WhoisRec) -> sled::IVec {
        serde_json::to_vec(&sv).unwrap().into()
    }
}
pub struct WhoisSvr {
    whs: WhoIs,
    dns: Vec<std::net::SocketAddr>,
    req_timeout: std::time::Duration,
    cache_valid: chrono::Duration,
    //cache: RwLock<HashMap<String, WhoisRec>>,
    db: sled::Db,
}
static INVALID_WHOIS: &[u8] = b"Invalid WHOIS query";

impl WhoisSvr {
    pub fn new(conf:&SvcConfig) -> WhoisSvr {
        WhoisSvr {
            whs: conf.whoisconfig.clone(),
            dns: conf.whoisdnses.clone(),
            req_timeout: std::time::Duration::from_secs(conf.whoisreqtimeout),
            cache_valid: chrono::Duration::seconds(conf.whoiscachesecs),
            db: sled::Config::default()
                .flush_every_ms(Some(10000))
                .path(conf.whoisdb.clone())
                .open()
                .unwrap(),
        }
    }
    pub fn invalid_query() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .body(INVALID_WHOIS.into())
            .unwrap()
    }
    pub async fn bindany() -> Result<tokio::net::UdpSocket, WhoIsError> {
        let mut bindport: u16 = 10000;
        for _i in 0..19 {
            match tokio::net::UdpSocket::bind(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                bindport,
            ))
            .await
            {
                Ok(s) => {
                    return Ok(s);
                }
                Err(_) => {}
            };
            bindport += 1;
        }
        return Err(WhoIsError::MapError("Unable to bind socket"));
    }
    pub async fn do_query_dns_ptr(
        self: &Arc<WhoisSvr>,
        target: String,
    ) -> Result<String, WhoIsError> {
        lazy_static! {
            static ref RE_IPV4: Regex =
                Regex::new(r"([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)").unwrap();
        }
        match RE_IPV4.captures(target.as_str()) {
            None => {}
            Some(caps) => {
                if let (Some(c1), Some(c2), Some(c3), Some(c4)) =
                    (caps.get(1), caps.get(2), caps.get(3), caps.get(4))
                {
                    let trg = String::new()
                        + c4.as_str()
                        + "."
                        + c3.as_str()
                        + "."
                        + c2.as_str()
                        + "."
                        + c1.as_str()
                        + ".IN-ADDR.ARPA.";
                    let res = match self.do_query_dns("PTR", trg).await {
                        Ok(q) => q,
                        Err(e) => return Err(e),
                    };
                    let lkey: sled::IVec = WhoisKey::dns_query(target.clone()).into();
                    self.db.insert(lkey, WhoisRec::new(res.clone())).unwrap();
                    return Ok(res);
                };
            }
        };
        Err(WhoIsError::MapError("Invalid IPv4"))
    }
    pub async fn query_dns_ptr(self: &Arc<WhoisSvr>, target: String) -> Result<String, WhoIsError> {
        let lkey: sled::IVec = WhoisKey::dns_query(target.clone()).into();
        match self.db.get(lkey.clone()) {
            Ok(r) => {
                if let Some(v) = r {
                    if v.len() > 0 {
                        match serde_json::from_slice::<WhoisRec>(&v) {
                            Ok(q) => {
                                if chrono::Local::now().signed_duration_since(q.modified())
                                    > self.cache_valid
                                {
                                    // run separate task to refresh cache data
                                    let slf = self.clone();
                                    tokio::spawn(async move { slf.do_query_dns_ptr(target).await });
                                }
                                return Ok(q.val);
                            }
                            Err(e) => {
                                eprintln!("Deserialize error: {:?}", e);
                            }
                        };
                    };
                };
            }
            Err(e) => eprintln!("sled error: {:?}", e),
        };
        self.do_query_dns_ptr(target).await
    }
    pub async fn do_query_dns(
        self: &Arc<WhoisSvr>,
        qtype: &str,
        target: String,
    ) -> Result<String, WhoIsError> {
        let mut parsed_query = dnssector::gen::query(
            target.as_bytes(),
            Type::from_string(qtype).unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let query_tid = parsed_query.tid();
        let query_question = parsed_query.question();
        if query_question.is_none() || parsed_query.flags() & DNS_FLAG_QR != 0 {
            return Err(WhoIsError::MapError("No DNS question"));
        }
        let valid_query = parsed_query.into_packet();
        let socket = Self::bindany().await?;
        socket
            .connect(self.dns[(target.as_bytes()[0] as usize) % self.dns.len()])
            .await?;
        socket.send(&valid_query).await?;
        let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
        let response_len = socket
            .recv(&mut response)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
        response.truncate(response_len);
        let mut parsed_response = DNSSector::new(response)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        if parsed_response.tid() != query_tid || parsed_response.question() != query_question {
            return Err(WhoIsError::MapError("Unexpected DNS response"));
        }
        {
            let mut it = parsed_response.into_iter_answer();
            while let Some(item) = it {
                if item.rr_type() == 12 {
                    //ptr
                    let mut res = String::new();
                    let rdata = item.rdata_slice();
                    let mut p: usize = DNS_RR_HEADER_SIZE;
                    while p < rdata.len() {
                        if (p + (rdata[p] as usize)) > rdata.len() {
                            break;
                        }
                        if rdata[p] > 0 {
                            //TODO: idna
                            res +=
                                String::from_utf8_lossy(&rdata[p + 1..p + 1 + (rdata[p] as usize)])
                                    .to_string()
                                    .as_str();
                            res += ".";
                        }
                        p += 1 + (rdata[p] as usize);
                    }
                    return Ok(res);
                }
                println!("DNS: {:?} - {:?}", item.rr_type(), item.rdata_slice());
                it = item.next();
            }
        };
        Err(WhoIsError::MapError("Not found"))
    }
    pub async fn do_query_whois(
        self: &Arc<WhoisSvr>,
        target: String,
        checkitem: Arc<Option<Regex>>,
    ) -> Result<String, WhoIsError> {
        lazy_static! {
            static ref RE_WHOIS: Regex = Regex::new(r"\b(whois\.[\.a-z0-9\-]+)\b").unwrap();
        }
        let lkey: sled::IVec = WhoisKey::whois_query(target.clone()).into();
        let mut deep: usize = 16;
        let mut whoises: HashMap<String, bool> = HashMap::new();
        while deep > 0 {
            deep -= 1;
            let mut opts = WhoIsLookupOptions::from_string(target.clone())?;
            opts.timeout = Some(self.req_timeout);
            if whoises.len() > 0 {
                loop {
                    let whfnd = match whoises.iter().find(|x| *x.1) {
                        None => return Ok(String::from("")),
                        Some(v) => v.0.clone(),
                    };
                    if whfnd.len() > 0 {
                        whoises.insert(whfnd.clone(), false);
                        opts.server = Some(match WhoIsServerValue::from_string(whfnd) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("Invalid whois server: {:?}", e);
                                continue;
                            }
                        });
                    };
                    break;
                }
            }
            let res = match self.whs.lookup_async(opts).await {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            match *checkitem {
                None => {
                    self.db.insert(lkey, WhoisRec::new(res.clone())).unwrap();
                    return Ok(res);
                }
                Some(_) => {
                    let v = Self::findstr(res.as_str(), &checkitem);
                    if v.len() > 0 {
                        self.db.insert(lkey, WhoisRec::new(res.clone())).unwrap();
                        return Ok(res);
                    };
                }
            };
            for i in RE_WHOIS.find_iter(res.as_str()) {
                let whoissvr = i.as_str();
                if !whoises.contains_key(whoissvr) {
                    whoises.insert(whoissvr.to_string(), true);
                };
            }
            if whoises.len() < 1 {
                return Ok(res);
            };
        }
        Err(WhoIsError::MapError("Search failed"))
    }
    pub async fn query_whois(
        self: &Arc<WhoisSvr>,
        target: String,
        checkitem: Arc<Option<Regex>>,
    ) -> Result<String, WhoIsError> {
        let lkey: sled::IVec = WhoisKey::whois_query(target.clone()).into();
        match self.db.get(lkey.clone()) {
            Ok(r) => {
                if let Some(v) = r {
                    if v.len() > 0 {
                        match serde_json::from_slice::<WhoisRec>(&v) {
                            Ok(q) => {
                                if chrono::Local::now().signed_duration_since(q.modified())
                                    > self.cache_valid
                                {
                                    let slf = self.clone();
                                    tokio::spawn(async move {
                                        slf.do_query_whois(target, checkitem).await
                                    });
                                }
                                return Ok(q.val);
                            }
                            Err(e) => {
                                eprintln!("Deserialize error: {:?}", e);
                            }
                        };
                    };
                };
            }
            Err(e) => eprintln!("sled error: {:?}", e),
        };
        self.do_query_whois(target, checkitem).await
    }
    fn filterout_comments<'a>(s: &'a str) -> Vec<&'a str> {
        s.split('\n')
            .filter(|q| {
                if q.len() > 0 {
                    if let Some(fc) = q.chars().next() {
                        return fc != '%';
                    }
                };
                false
            })
            .collect()
    }
    fn findstr<'a>(s: &'a str, tofind: &Option<Regex>) -> Vec<&'a str> {
        match tofind {
            None => Self::filterout_comments(s),
            Some(fnd) => s
                .split('\n')
                .filter(|q| {
                    if q.len() > 0 {
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
    pub async fn handle_query(
        self: &Arc<WhoisSvr>,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let requri = req.uri().path();
        let urlparts: Vec<&str> = requri.split('/').collect();
        if urlparts.len() < 3 {
            return Ok(not_found());
        }
        if urlparts.len() > 3 && urlparts[1] == "api" && urlparts[2] == "dns" {
            let rsp = match self.query_dns_ptr(urlparts[3].to_string()).await {
                Ok(v) => v,
                Err(e) => {
                    return Response::builder()
                        .status(StatusCode::from_u16(500).unwrap())
                        .header("Content-type", "text/plain")
                        .body(format!("Error: {:?}", e).into());
                }
            };
            return Response::builder()
                .status(StatusCode::OK)
                .header("Content-type", "text/plain")
                .body(rsp.into());
        }
        if urlparts[1] != "api" || urlparts[2] != "whois" {
            return Ok(not_found());
        }
        let params = get_url_params(req);
        let query = match get_url_param::<String>(&params, "query") {
            Some(s) => s,
            None => {
                return Ok(WhoisSvr::invalid_query());
            }
        };
        if query.len() < 1 {
            return Ok(WhoisSvr::invalid_query());
        };
        let checkstr = Arc::new(if urlparts.len() >= 4 {
            match urlparts[3] {
                "aut-num" | "as" => Some(Regex::new(r"(aut-num|ASNumber):").unwrap()),
                "r" | "r4" | "route" => Some(Regex::new(r"route:").unwrap()),
                "r6" | "route6" => Some(Regex::new(r"route6:").unwrap()),
                _ => None,
            }
        } else {
            None
        });
        let mut rsp = match self.query_whois(query, checkstr.clone()).await {
            Ok(v) => v,
            Err(e) => {
                return Response::builder()
                    .status(StatusCode::from_u16(500).unwrap())
                    .header("Content-type", "text/plain")
                    .body(format!("Error: {:?}", e).into());
            }
        };
        if urlparts.len() >= 4 {
            match urlparts[3] {
                "raw" => {}
                _ => {
                    rsp = {
                        let v = Self::findstr(rsp.as_str(), &*checkstr);
                        if v.len() > 0 {
                            v.join("\n")
                        } else {
                            Self::filterout_comments(rsp.as_str()).join("\n")
                        }
                    };
                }
            }
        }
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-type", "text/plain")
            .body(rsp.into())
    }
    pub async fn response_fn(
        self: &Arc<WhoisSvr>,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        //Ok(not_found())
        match self.handle_query(req).await {
            Ok(v) => Ok(v),
            Err(e) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(format!("{:?}", e).into())
                .unwrap()),
        }
    }
}
