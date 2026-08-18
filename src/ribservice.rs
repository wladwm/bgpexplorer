use crate::bgpattrs::{BgpAttrEntry, BgpAttrs};
use crate::bgprib::*;
use crate::service::*;
use crate::timestamp::Timestamp;
use crate::*;
use chrono::prelude::*;
use futures::executor::block_on;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::*;
use tokio::sync::RwLock;
use tokio::time::timeout;
use zettabgp::prelude::*;

const HTTP_CONTENT_TYPE: &'static str = "Content-Type";
const HTTP_CONTENT_DISPOSITION: &'static str = "Content-Disposition";
const HTTP_CT_TEXT_PLAIN: &'static str = "text/plain";
const HTTP_CT_TEXT_JSON: &'static str = "text/json";

const KEY_PATHES: &'static str = "pathes";
const KEY_COMMUNITIES: &'static str = "comms";
const KEY_LARGE_COMMUNITIES: &'static str = "lcomms";
const KEY_EXT_COMMUNITIES: &'static str = "extcomms";
const KEY_ATTRS: &'static str = "attrs";
const KEY_CLUSTERS: &'static str = "clusters";
const KEY_STORES: &'static str = "stores";
const KEY_IPV4U: &'static str = "ipv4u";
const KEY_IPV4M: &'static str = "ipv4m";
const KEY_IPV4LU: &'static str = "ipv4lu";
const KEY_VPNV4U: &'static str = "vpnv4u";
const KEY_VPNV4M: &'static str = "vpnv4m";
const KEY_IPV6U: &'static str = "ipv6u";
const KEY_IPV6LU: &'static str = "ipv6lu";
const KEY_VPNV6U: &'static str = "vpnv6u";
const KEY_VPNV6M: &'static str = "vpnv6m";
const KEY_L2VPLS: &'static str = "l2vpls";
const KEY_MVPN: &'static str = "mvpn";
const KEY_EVPN: &'static str = "evpn";
const KEY_FS4U: &'static str = "fs4u";
const KEY_FS6U: &'static str = "fs6u";
const KEY_IPV4MDT: &'static str = "ipv4mdt";
const KEY_IPV6MDT: &'static str = "ipv6mdt";

fn http_err<E: std::error::Error>(e: E) -> Result<Response<Body>, hyper::http::Error> {
    Response::builder()
        .status(StatusCode::from_u16(500).unwrap())
        .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_PLAIN)
        .body(format!("Error: {:?}", e).into())
}

#[derive(Clone)]
pub struct RibResponseFilter {
    pub maxdepth: usize,
    pub onlyactive: bool,
    pub changed_before: Option<Timestamp>,
    pub changed_after: Option<Timestamp>,
    pub sessionid: Option<u16>,
}
impl std::default::Default for RibResponseFilter {
    fn default() -> Self {
        RibResponseFilter {
            maxdepth: 10,
            onlyactive: false,
            changed_before: None,
            changed_after: None,
            sessionid: None,
        }
    }
}
impl RibResponseFilter {
    pub fn new(maxdepth: usize, onlyactive: bool) -> RibResponseFilter {
        RibResponseFilter {
            maxdepth,
            onlyactive,
            changed_before: None,
            changed_after: None,
            sessionid: None,
        }
    }
    pub fn extract_params(&mut self, hashmap: &HashMap<String, String>) {
        if let Some(n) = get_url_param(hashmap, "maxdepth") {
            self.maxdepth = n;
        };
        self.onlyactive = get_url_param(hashmap, "onlyactive").unwrap_or(false);
        self.changed_before = get_url_param(hashmap, "changed_before");
        self.changed_after = get_url_param(hashmap, "changed_after");
        self.sessionid = get_url_param(hashmap, "sessionid");
    }
    pub fn filter_session(&self, session_id: u16) -> bool {
        if self.sessionid.is_none() {
            return true;
        }
        *self.sessionid.as_ref().unwrap() == session_id
    }
    pub fn filter_path_e(&self, bp: &BgpAttrHistory) -> bool {
        if self.onlyactive {
            if !bp
                .items
                .iter()
                .next_back()
                .map(|x| x.1.active)
                .unwrap_or(false)
            {
                return false;
            }
        }
        if let Some(cb) = self.changed_before.as_ref() {
            if bp
                .items
                .range(..*cb)
                .find(|(ts, ba)| self.filter_ah(ts, ba))
                .is_none()
            {
                return false;
            }
        }
        if let Some(ca) = self.changed_after.as_ref() {
            if bp
                .items
                .range(*ca..)
                .find(|(ts, ba)| self.filter_ah(ts, ba))
                .is_none()
            {
                return false;
            }
        }
        true
    }
    pub fn filter_ah(&self, ts: &Timestamp, ba: &crate::bgpattrs::BgpAttrEntry) -> bool {
        if self.onlyactive {
            if !ba.active {
                return false;
            }
        }
        if let Some(cb) = self.changed_before.as_ref() {
            if ts >= cb {
                return false;
            }
        }
        if let Some(ca) = self.changed_after.as_ref() {
            if ts <= ca {
                return false;
            }
        }
        true
    }
}
#[derive(Clone)]
pub struct RibResponseParams {
    pub skip: usize,
    pub limit: usize,
    pub filter: RibResponseFilter,
}
impl std::default::Default for RibResponseParams {
    fn default() -> Self {
        RibResponseParams {
            skip: 0,
            limit: 1000,
            filter: Default::default(),
        }
    }
}
impl RibResponseParams {
    pub fn new(skip: usize, limit: usize, filter: RibResponseFilter) -> RibResponseParams {
        RibResponseParams {
            skip,
            limit,
            filter,
        }
    }
    pub fn extract_params(&mut self, hashmap: &HashMap<String, String>) {
        if let Some(n) = get_url_param(hashmap, "skip") {
            self.skip = n;
        };
        if let Some(n) = get_url_param(hashmap, "limit") {
            self.limit = n;
        };
        self.filter.extract_params(hashmap);
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
    pub async fn register_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> BgpSessionId {
        self.rib.read().await.register_session(sess, offer).await
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
                    .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_PLAIN)
                    .body("Operation timed out".into());
            }
        };
        let mut rsp: std::collections::HashMap<&str, std::collections::HashMap<&str, u64>> =
            std::collections::HashMap::new();
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert(KEY_PATHES, rib.pathes.len() as u64);
        m.insert(KEY_COMMUNITIES, rib.comms.len() as u64);
        m.insert(KEY_LARGE_COMMUNITIES, rib.lcomms.len() as u64);
        m.insert(KEY_EXT_COMMUNITIES, rib.extcomms.len() as u64);
        m.insert(KEY_ATTRS, rib.attrs.len() as u64);
        m.insert(KEY_CLUSTERS, rib.clusters.len() as u64);
        rsp.insert(KEY_STORES, m);
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert(KEY_IPV4U, rib.ipv4u.len() as u64);
        m.insert(KEY_IPV4M, rib.ipv4m.len() as u64);
        m.insert(KEY_IPV4LU, rib.ipv4lu.len() as u64);
        m.insert(KEY_VPNV4U, rib.vpnv4u.len() as u64);
        m.insert(KEY_VPNV4M, rib.vpnv4m.len() as u64);
        m.insert(KEY_IPV6U, rib.ipv6u.len() as u64);
        m.insert(KEY_IPV6LU, rib.ipv6lu.len() as u64);
        m.insert(KEY_VPNV6U, rib.vpnv6u.len() as u64);
        m.insert(KEY_VPNV6M, rib.vpnv6m.len() as u64);
        m.insert(KEY_L2VPLS, rib.l2vpls.len() as u64);
        m.insert(KEY_MVPN, rib.mvpn.len() as u64);
        m.insert(KEY_EVPN, rib.evpn.len() as u64);
        m.insert(KEY_FS4U, rib.fs4u.len() as u64);
        m.insert(KEY_FS6U, rib.fs6u.len() as u64);
        m.insert(KEY_IPV4MDT, rib.ipv4mdt.len() as u64);
        m.insert(KEY_IPV6MDT, rib.ipv6mdt.len() as u64);
        rsp.insert("ribs", m);
        let mut m: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        m.insert("updates", rib.cnt_updates);
        m.insert("withdraws", rib.cnt_withdraws);
        rsp.insert("counters", m);
        match serde_json::to_vec(&rsp) {
            Ok(v) => Response::builder()
                .status(StatusCode::OK)
                .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_JSON)
                .body(v.into()),
            Err(e) => http_err(e),
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
                .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_JSON)
                .body(v.into()),
            Err(e) => http_err(e),
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
                    .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_PLAIN)
                    .body("Operation timed out".into());
            }
        };
        let mut params = RibResponseParams::default();
        let mut filter = ribfilter::RouteFilter::new();
        let paramshm = get_url_params(req);
        params.extract_params(&paramshm);
        if let Some(s) = get_url_param::<String>(&paramshm, "filter") {
            filter.parse(s.as_str());
        };
        match queryrib {
            KEY_IPV4U => BgpRIBts::jsontabrib(&rib.ipv4u, &filter, params),
            KEY_IPV4M => BgpRIBts::jsontabrib(&rib.ipv4m, &filter, params),
            KEY_IPV4LU => BgpRIBts::jsontabrib(&rib.ipv4lu, &filter, params),
            KEY_VPNV4U => BgpRIBts::jsontabrib(&rib.vpnv4u, &filter, params),
            KEY_VPNV4M => BgpRIBts::jsontabrib(&rib.vpnv4m, &filter, params),
            KEY_IPV6U => BgpRIBts::jsontabrib(&rib.ipv6u, &filter, params),
            KEY_IPV6LU => BgpRIBts::jsontabrib(&rib.ipv6lu, &filter, params),
            KEY_VPNV6U => BgpRIBts::jsontabrib(&rib.vpnv6u, &filter, params),
            KEY_VPNV6M => BgpRIBts::jsontabrib(&rib.vpnv6m, &filter, params),
            KEY_L2VPLS => BgpRIBts::jsontabrib(&rib.l2vpls, &filter, params),
            KEY_MVPN => BgpRIBts::jsontabrib(&rib.mvpn, &filter, params),
            KEY_EVPN => BgpRIBts::jsontabrib(&rib.evpn, &filter, params),
            KEY_FS4U => BgpRIBts::jsontabrib(&rib.fs4u, &filter, params),
            KEY_FS6U => BgpRIBts::jsontabrib(&rib.fs6u, &filter, params),
            KEY_IPV4MDT => BgpRIBts::jsontabrib(&rib.ipv4mdt, &filter, params),
            KEY_IPV6MDT => BgpRIBts::jsontabrib(&rib.ipv6mdt, &filter, params),
            _ => BgpRIBts::jsontabrib(&rib.ipv4u, &filter, params),
        }
    }
    pub fn csvtabrib<
        T: serde::Serialize + ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString,
    >(
        rib: &BgpRIBSafi<T>,
        filter: &ribfilter::RouteFilter,
        params: RibResponseParams,
        fname: Option<&str>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let rsp = RibResponse::<T>::new(rib, filter, params);
        let mut buf = bytes::BytesMut::new();
        let mut header: Vec<&'static str> = vec!["TIME", "ROUTE"];
        header.extend_from_slice(&BgpAttrEntry::COLS);
        header.extend_from_slice(&BgpAttrs::COLS);
        for c in header.iter().enumerate() {
            if c.0 > 0 {
                if let Err(e) = write!(&mut buf, "\t") {
                    return http_err(e);
                }
            }
            if let Err(e) = write!(&mut buf, "{}", *c.1) {
                return http_err(e);
            }
        }
        if let Err(e) = writeln!(&mut buf, "") {
            return http_err(e);
        }
        for (k, v) in rsp.iter() {
            let v1 = BSEItems::new(v, &rsp.params);
            if v1.is_empty() {
                continue;
            }
            for (sid, v) in v1.bse.items.iter() {
                if !rsp.params.filter.filter_session(*sid) {
                    continue;
                }
                let v2 = BPEItems::new(v, &rsp.params);
                if v2.is_empty() {
                    continue;
                }
                for (_, h) in v2.bpe.items.iter() {
                    let v = BAHItems::new(h, &rsp.params);
                    if v.is_empty() {
                        continue;
                    }
                    if !rsp.params.filter.filter_path_e(h) {
                        continue;
                    }
                    for (ts, v) in v.bah.items.iter() {
                        if !rsp.params.filter.filter_ah(ts, v) {
                            continue;
                        }
                        if let Err(e) = writeln!(&mut buf, "{}\t{}\t{}", ts, k, v) {
                            return http_err(e);
                        }
                    }
                }
            }
        }
        let mut rsp = Response::builder()
            .status(StatusCode::OK)
            .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_PLAIN);
        if let Some(fnm) = fname {
            rsp = rsp.header(
                HTTP_CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", fnm),
            )
        }
        rsp.body(buf.freeze().into())
    }
    pub async fn say_csvrib(
        &self,
        queryrib: &str,
        req: &Request<Body>,
        fname: Option<&str>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let rib = match timeout(self.locktimeout, self.rib.read()).await {
            Ok(r) => r,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::from_u16(408).unwrap())
                    .header(HTTP_CONTENT_TYPE, HTTP_CT_TEXT_PLAIN)
                    .body("Operation timed out".into());
            }
        };
        let mut params = RibResponseParams::default();
        let mut filter = ribfilter::RouteFilter::new();
        let paramshm = get_url_params(req);
        params.extract_params(&paramshm);
        if let Some(s) = get_url_param::<String>(&paramshm, "filter") {
            filter.parse(s.as_str());
        };
        match queryrib {
            KEY_IPV4U => BgpRIBts::csvtabrib(&rib.ipv4u, &filter, params, fname),
            KEY_IPV4M => BgpRIBts::csvtabrib(&rib.ipv4m, &filter, params, fname),
            KEY_IPV4LU => BgpRIBts::csvtabrib(&rib.ipv4lu, &filter, params, fname),
            KEY_VPNV4U => BgpRIBts::csvtabrib(&rib.vpnv4u, &filter, params, fname),
            KEY_VPNV4M => BgpRIBts::csvtabrib(&rib.vpnv4m, &filter, params, fname),
            KEY_IPV6U => BgpRIBts::csvtabrib(&rib.ipv6u, &filter, params, fname),
            KEY_IPV6LU => BgpRIBts::csvtabrib(&rib.ipv6lu, &filter, params, fname),
            KEY_VPNV6U => BgpRIBts::csvtabrib(&rib.vpnv6u, &filter, params, fname),
            KEY_VPNV6M => BgpRIBts::csvtabrib(&rib.vpnv6m, &filter, params, fname),
            KEY_L2VPLS => BgpRIBts::csvtabrib(&rib.l2vpls, &filter, params, fname),
            KEY_MVPN => BgpRIBts::csvtabrib(&rib.mvpn, &filter, params, fname),
            KEY_EVPN => BgpRIBts::csvtabrib(&rib.evpn, &filter, params, fname),
            KEY_FS4U => BgpRIBts::csvtabrib(&rib.fs4u, &filter, params, fname),
            KEY_FS6U => BgpRIBts::csvtabrib(&rib.fs6u, &filter, params, fname),
            KEY_IPV4MDT => BgpRIBts::csvtabrib(&rib.ipv6mdt, &filter, params, fname),
            KEY_IPV6MDT => BgpRIBts::csvtabrib(&rib.ipv6mdt, &filter, params, fname),
            _ => BgpRIBts::csvtabrib(&rib.ipv4u, &filter, params, fname),
        }
    }
}
