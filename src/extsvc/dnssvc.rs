use super::{StoreKey, StoreVal};
use crate::config::SvcConfig;
use dnssector::*;
use regex::Regex;
use std::sync::Arc;

pub struct DnsSvr {
    dns: Vec<std::net::SocketAddr>,
    dnstimeout: std::time::Duration,
    cache_valid: chrono::Duration,
    db: Arc<sled::Db>,
}

impl DnsSvr {
    pub fn new(conf: &SvcConfig, db: Arc<sled::Db>) -> DnsSvr {
        DnsSvr {
            dns: conf.dns.dnses.clone(),
            dnstimeout: conf.dns.timeout.into(),
            cache_valid: conf.cache_valid.into(),
            db,
        }
    }
    pub async fn bindany() -> anyhow::Result<tokio::net::UdpSocket> {
        let mut bindport: u16 = 10000;
        for _i in 0..19 {
            if let Ok(s) = tokio::net::UdpSocket::bind(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                bindport,
            ))
            .await
            {
                return Ok(s);
            };
            bindport += 1;
        }
        Err(anyhow!("Unable to bind udp socket"))
    }
    pub async fn do_query_dns_ptr(self: &Arc<DnsSvr>, target: String) -> anyhow::Result<String> {
        lazy_static! {
            static ref RE_IPV4: Regex =
                Regex::new(r"([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)").unwrap();
        }
        match RE_IPV4.captures(target.as_str()) {
            None => {
                if let Ok(ipv6) = target.parse::<std::net::Ipv6Addr>() {
                    let oct = ipv6.octets();
                    let mut trg: String = "".to_string();
                    for o in oct.iter().rev() {
                        trg += format!("{:x}.{:x}.", o & 0xf, (o >> 4)).as_str();
                    }
                    trg += "ip6.arpa.";
                    let res = match self.do_query_dns("PTR", trg).await {
                        Ok(q) => q,
                        Err(e) => return Err(e),
                    };
                    let lkey: sled::IVec = StoreKey::dns_query(format!("{}", ipv6)).into();
                    self.db.insert(lkey, StoreVal::new(res.clone()))?;
                    return Ok(res);
                }
            }
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
                    let lkey: sled::IVec = StoreKey::dns_query(target).into();
                    self.db.insert(lkey, StoreVal::new(res.clone()))?;
                    return Ok(res);
                };
            }
        };
        Err(anyhow!("Invalid IP"))
    }
    pub async fn query_dns_ptr(self: &Arc<DnsSvr>, target: String) -> anyhow::Result<String> {
        let lkey: sled::IVec = StoreKey::dns_query(target.clone()).into();
        match self.db.get(lkey.clone()) {
            Ok(r) => {
                if let Some(v) = r {
                    if v.len() > 0 {
                        match serde_json::from_slice::<StoreVal>(&v) {
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
                                warn!("Deserialize error: {:?}", e);
                            }
                        };
                    };
                };
            }
            Err(e) => warn!("sled error: {:?}", e),
        };
        self.do_query_dns_ptr(target).await
    }
    pub async fn do_query_dns(
        self: &Arc<DnsSvr>,
        qtype: &str,
        target: String,
    ) -> anyhow::Result<String> {
        let mut parsed_query = dnssector::gen::query(
            target.as_bytes(),
            Type::from_string(qtype).unwrap(),
            Class::from_string("IN").unwrap(),
        )?;
        let query_tid = parsed_query.tid();
        let query_question = parsed_query.question();
        if query_question.is_none() || parsed_query.flags() & DNS_FLAG_QR != 0 {
            return Err(anyhow!("No DNS question"));
        }
        let valid_query = parsed_query.into_packet();
        let socket = Self::bindany().await?;
        socket
            .connect(self.dns[(target.as_bytes()[0] as usize) % self.dns.len()])
            .await?;
        socket.send(&valid_query).await?;
        let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
        let response_len =
            tokio::time::timeout(self.dnstimeout.into(), socket.recv(&mut response)).await??;
        response.truncate(response_len);
        let mut parsed_response = DNSSector::new(response)?.parse()?;
        if parsed_response.tid() != query_tid || parsed_response.question() != query_question {
            return Err(anyhow!("Unexpected DNS response"));
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
                debug!("DNS: {:?} - {:?}", item.rr_type(), item.rdata_slice());
                it = item.next();
            }
        };
        Err(anyhow!("Not found"))
    }
}
