use crate::bgprib::*;
use crate::service::*;
use crate::*;
use chrono::prelude::*;
use futures::executor::block_on;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::*;
use tokio::sync::RwLock;
use tokio::time::timeout;
use zettabgp::prelude::*;

#[derive(Clone)]
pub struct RibResponseParams {
    pub skip: usize,
    pub limit: usize,
    pub maxdepth: usize,
    pub onlyactive: bool,
}
impl RibResponseParams {
    pub fn new(skip: usize, limit: usize, maxdepth: usize, onlyactive: bool) -> RibResponseParams {
        RibResponseParams {
            skip,
            limit,
            maxdepth,
            onlyactive,
        }
    }
    pub fn extract_params(&mut self, hashmap: &HashMap<String, String>) {
        if let Some(n) = get_url_param(hashmap, "skip") {
            self.skip = n;
        };
        if let Some(n) = get_url_param(hashmap, "limit") {
            self.limit = n;
        };
        if let Some(n) = get_url_param(hashmap, "maxdepth") {
            self.maxdepth = n;
        };
        if let Some(n) = get_url_param(hashmap, "onlyactive") {
            self.onlyactive = n;
        };
    }
}

pub struct BgpRIBts {
    pub locktimeout: Duration,
    pub rib: Arc<RwLock<BgpRIB>>,
}
impl BgpRIBts {
    pub fn new(cfg: &SvcConfig, rib: BgpRIB) -> BgpRIBts {
        BgpRIBts {
            locktimeout: Duration::from_secs(cfg.httptimeout),
            rib: Arc::new(RwLock::new(rib)),
        }
    }
    pub async fn shutdown(&self) {
        self.rib.read().await.shutdown().await;
    }
    pub fn run(
        &self,
        mut rx: Receiver<Option<(BgpSessionId, BgpUpdateMessage)>>,
    ) -> std::thread::JoinHandle<()> {
        let ribc = self.rib.clone();
        let builderp = std::thread::Builder::new().name("bgp_garbage_collector".into());
        builderp
            .spawn(move || loop {
                std::thread::sleep(time::Duration::from_secs(10));
                if !block_on(ribc.read()).needs_purge() {
                    continue;
                }
                block_on(ribc.write()).purge();
            })
            .unwrap();
        let ribc = self.rib.clone();
        let builderu = std::thread::Builder::new().name("bgp_updates_handler".into());
        builderu
            .spawn(move || {
                while let Some(updmsg) = rx.blocking_recv() {
                    match updmsg {
                        Some(updm) => {
                            let time_started = Local::now();
                            if let Err(e) = block_on(ribc.write()).handle_update(updm.0, updm.1) {
                                warn!("RIB handle_update: {:?}", e);
                            };
                            let time_done = Local::now();
                            let took = time_done - time_started;
                            if took > chrono::Duration::seconds(1) {
                                warn!("{} Warning: BGP update took {}", time_started, took);
                            }
                        }
                        None => break,
                    }
                }
            })
            .unwrap()
    }
    pub async fn say_statistics(&self) -> Result<Response<Body>, hyper::http::Error> {
        let rib = match timeout(self.locktimeout, self.rib.read()).await {
            Ok(r) => r,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::from_u16(408).unwrap())
                    .header("Content-type", "text/plain")
                    .body("Operation timed out".into());
            }
        };
        let mut rsp: std::collections::HashMap<&str, std::collections::HashMap<&str, u64>> =
            std::collections::HashMap::new();
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert("pathes", rib.pathes.len() as u64);
        m.insert("comms", rib.comms.len() as u64);
        m.insert("lcomms", rib.lcomms.len() as u64);
        m.insert("extcomms", rib.extcomms.len() as u64);
        m.insert("attrs", rib.attrs.len() as u64);
        m.insert("clusters", rib.clusters.len() as u64);
        rsp.insert("stores", m);
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert("ipv4u", rib.ipv4u.len() as u64);
        m.insert("ipv4m", rib.ipv4m.len() as u64);
        m.insert("ipv4lu", rib.ipv4lu.len() as u64);
        m.insert("vpnv4u", rib.vpnv4u.len() as u64);
        m.insert("vpnv4m", rib.vpnv4m.len() as u64);
        m.insert("ipv6u", rib.ipv6u.len() as u64);
        m.insert("ipv6lu", rib.ipv6lu.len() as u64);
        m.insert("vpnv6u", rib.vpnv6u.len() as u64);
        m.insert("vpnv6m", rib.vpnv6m.len() as u64);
        m.insert("l2vpls", rib.l2vpls.len() as u64);
        m.insert("mvpn", rib.mvpn.len() as u64);
        m.insert("evpn", rib.evpn.len() as u64);
        m.insert("fs4u", rib.fs4u.len() as u64);
        m.insert("ipv4mdt", rib.ipv4mdt.len() as u64);
        m.insert("ipv6mdt", rib.ipv6mdt.len() as u64);
        rsp.insert("ribs", m);
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert("updates", rib.cnt_updates);
        m.insert("withdraws", rib.cnt_withdraws);
        rsp.insert("counters", m);
        match serde_json::to_vec(&rsp) {
            Ok(v) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-type", "text/json")
                .body(v.into()),
            Err(e) => Response::builder()
                .status(StatusCode::from_u16(500).unwrap())
                .header("Content-type", "text/plain")
                .body(format!("Error: {:?}", e).into()),
        }
    }
    pub fn jsontabrib<
        T: serde::Serialize + ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString,
    >(
        rib: &BgpRIBSafi<T>,
        filter: &ribfilter::RouteFilter,
        params: RibResponseParams,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let rsp = RibResponse::<T>::new(rib, filter, params);
        match serde_json::to_vec(&rsp) {
            Ok(v) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-type", "text/json")
                .body(v.into()),
            Err(e) => Response::builder()
                .status(StatusCode::from_u16(500).unwrap())
                .header("Content-type", "text/plain")
                .body(format!("Error: {:?}", e).into()),
        }
    }
    pub async fn say_jsonrib(
        &self,
        queryrib: &str,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let rib = match timeout(self.locktimeout, self.rib.read()).await {
            Ok(r) => r,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::from_u16(408).unwrap())
                    .header("Content-type", "text/plain")
                    .body("Operation timed out".into());
            }
        };
        let mut params = RibResponseParams::new(0, 1000, 10, false);
        let mut filter = ribfilter::RouteFilter::new();
        let paramshm = get_url_params(req);
        params.extract_params(&paramshm);
        if let Some(s) = get_url_param::<String>(&paramshm, "filter") {
            filter.parse(s.as_str());
        };
        match queryrib {
            "ipv4u" => BgpRIBts::jsontabrib(&rib.ipv4u, &filter, params),
            "ipv4m" => BgpRIBts::jsontabrib(&rib.ipv4m, &filter, params),
            "ipv4lu" => BgpRIBts::jsontabrib(&rib.ipv4lu, &filter, params),
            "vpnv4u" => BgpRIBts::jsontabrib(&rib.vpnv4u, &filter, params),
            "vpnv4m" => BgpRIBts::jsontabrib(&rib.vpnv4m, &filter, params),
            "ipv6u" => BgpRIBts::jsontabrib(&rib.ipv6u, &filter, params),
            "ipv6lu" => BgpRIBts::jsontabrib(&rib.ipv6lu, &filter, params),
            "vpnv6u" => BgpRIBts::jsontabrib(&rib.vpnv6u, &filter, params),
            "vpnv6m" => BgpRIBts::jsontabrib(&rib.vpnv6m, &filter, params),
            "l2vpls" => BgpRIBts::jsontabrib(&rib.l2vpls, &filter, params),
            "mvpn" => BgpRIBts::jsontabrib(&rib.mvpn, &filter, params),
            "evpn" => BgpRIBts::jsontabrib(&rib.evpn, &filter, params),
            "fs4u" => BgpRIBts::jsontabrib(&rib.fs4u, &filter, params),
            "ipv4mdt" => BgpRIBts::jsontabrib(&rib.ipv4mdt, &filter, params),
            "ipv6mdt" => BgpRIBts::jsontabrib(&rib.ipv6mdt, &filter, params),
            _ => BgpRIBts::jsontabrib(&rib.ipv4u, &filter, params),
        }
    }
}
