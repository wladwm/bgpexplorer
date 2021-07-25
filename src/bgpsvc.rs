use crate::bgppeer::*;
use crate::bgprib::*;
use crate::bmppeer::*;
use crate::ribservice::*;
use crate::*;
use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use serde::ser::{SerializeMap, SerializeStruct};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::thread::JoinHandle;
use std::vec::Vec;
use tokio::net::TcpSocket;
use tokio::sync::mpsc::*;
use tokio::sync::RwLock;
use tokio::time::timeout;
use zettabgp::bmp::prelude::*;
use zettabgp::prelude::*;

pub type BgpSessionId = u16;
#[async_trait]
pub trait BgpUpdateHandler {
    async fn handle_update(&self, peerid: BgpSessionId, upd: BgpUpdateMessage);
    async fn register_session(&self, sess: Arc<BgpSessionDesc>) -> BgpSessionId;
}
#[derive(Hash, Eq, Ord, Debug, Clone)]
pub struct BgpPeerDesc {
    pub addr: IpAddr,
    pub bom: BgpOpenMessage,
}
impl BgpPeerDesc {
    pub fn new(addr: IpAddr, bom: BgpOpenMessage) -> BgpPeerDesc {
        BgpPeerDesc {
            addr: addr,
            bom: bom,
        }
    }
}
impl PartialOrd for BgpPeerDesc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.addr.partial_cmp(&other.addr) {
            None => self.bom.as_num.partial_cmp(&other.bom.as_num),
            Some(pc) => match pc {
                Ordering::Less => Some(Ordering::Less),
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Equal => self.bom.as_num.partial_cmp(&other.bom.as_num),
            },
        }
    }
}
impl PartialEq for BgpPeerDesc {
    fn eq(&self, other: &Self) -> bool {
        self.addr.eq(&other.addr) && self.bom.as_num == other.bom.as_num
    }
}
#[derive(Hash, Eq, Ord, Debug, Clone)]
pub struct BgpSessionDesc {
    pub peer1: BgpPeerDesc,
    pub peer2: BgpPeerDesc,
}
impl BgpSessionDesc {
    pub fn new(peer1: BgpPeerDesc, peer2: BgpPeerDesc) -> BgpSessionDesc {
        BgpSessionDesc {
            peer1: peer1,
            peer2: peer2,
        }
    }
    pub fn from_bmppeerup(pu: &BmpMessagePeerUp) -> BgpSessionDesc {
        BgpSessionDesc {
            peer1: BgpPeerDesc::new(pu.localaddress.clone(), pu.msg1.clone()),
            peer2: BgpPeerDesc::new(pu.peer.peeraddress.clone(), pu.msg2.clone()),
        }
    }
}
impl PartialOrd for BgpSessionDesc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut sp1 = &self.peer1;
        let mut sp2 = &self.peer2;
        if sp2 < sp1 {
            sp1 = &self.peer2;
            sp2 = &self.peer1;
        }
        let mut op1 = &other.peer1;
        let mut op2 = &other.peer2;
        if op2 < op1 {
            op1 = &other.peer2;
            op2 = &other.peer1;
        }
        match sp1.partial_cmp(op1) {
            None => sp2.partial_cmp(op2),
            Some(pc) => match pc {
                Ordering::Less => Some(Ordering::Less),
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Equal => sp2.partial_cmp(op2),
            },
        }
    }
}
impl PartialEq for BgpSessionDesc {
    fn eq(&self, other: &Self) -> bool {
        (self.peer1.eq(&other.peer1) && self.peer2.eq(&other.peer2))
            || (self.peer1.eq(&other.peer2) && self.peer2.eq(&other.peer1))
    }
}
struct BgpSessionStorage {
    pub ss_ids: BTreeMap<BgpSessionId, Arc<BgpSessionDesc>>,
    pub ss_addrs: BTreeMap<Arc<BgpSessionDesc>, BgpSessionId>,
}
impl BgpSessionStorage {
    fn new() -> BgpSessionStorage {
        BgpSessionStorage {
            ss_ids: BTreeMap::new(),
            ss_addrs: BTreeMap::new(),
        }
    }
    fn register_session(&mut self, sess: Arc<BgpSessionDesc>) -> BgpSessionId {
        if let Some(x) = self.ss_addrs.get_key_value(&sess) {
            return *x.1;
        }
        let sessdsc = Arc::new(BgpSessionDesc::new(sess.peer2.clone(), sess.peer1.clone()));
        if let Some(x) = self.ss_addrs.get_key_value(&sessdsc) {
            return *x.1;
        }
        let mut nid: BgpSessionId = (self.ss_ids.len() + 1) as BgpSessionId;
        while self.ss_ids.get_key_value(&nid).is_some() {
            nid = nid + 1;
        }
        self.ss_addrs.insert(sessdsc.clone(), nid);
        self.ss_ids.insert(nid, sessdsc);
        nid
    }
}
pub struct BgpSvr {
    pub config: Arc<SvcConfig>,
    pub cancellation: tokio_util::sync::CancellationToken,
    pub rib: BgpRIBts,
    sessions: Arc<RwLock<BgpSessionStorage>>,
    upd: Option<Sender<Option<(BgpSessionId, BgpUpdateMessage)>>>,
    updater: Option<JoinHandle<()>>,
}
#[async_trait]
impl BgpUpdateHandler for BgpSvr {
    async fn handle_update(&self, sid: BgpSessionId, upd: BgpUpdateMessage) {
        match self.upd {
            None => eprintln!("Skip update"),
            Some(ref updch) => match updch.send(Some((sid, upd))).await {
                Ok(_) => {}
                Err(e) => eprintln!("Queued update error: {:?}", e),
            },
        };
    }
    async fn register_session(&self, sess: Arc<BgpSessionDesc>) -> BgpSessionId {
        self.sessions.write().await.register_session(sess)
    }
}
impl BgpSvr {
    pub fn new(cfg: Arc<SvcConfig>, cancel_token: tokio_util::sync::CancellationToken) -> BgpSvr {
        BgpSvr {
            config: cfg.clone(),
            cancellation: cancel_token,
            rib: BgpRIBts::new(&cfg),
            sessions: Arc::new(RwLock::new(BgpSessionStorage::new())),
            upd: None,
            updater: None,
        }
    }
    fn def_caps(asn: u32) -> Vec<BgpCapability> {
        vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::SafiIPv4fu,
            BgpCapability::SafiVPNv4fu,
            BgpCapability::SafiIPv4m,
            BgpCapability::SafiIPv4lu,
            BgpCapability::SafiIPv6lu,
            BgpCapability::SafiIPv6fu,
            BgpCapability::SafiVPNv4u,
            BgpCapability::SafiVPNv4m,
            BgpCapability::SafiVPNv6u,
            BgpCapability::SafiVPNv6m,
            BgpCapability::SafiIPv4mvpn,
            BgpCapability::SafiVPLS,
            BgpCapability::SafiEVPN,
            BgpCapability::CapASN32(asn),
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiIPv4u, true, true).unwrap(),
            ),
            /*
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiIPv4lu, true, true).unwrap(),
            ),
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiIPv6u, true, true).unwrap(),
            ),
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiIPv6lu, true, true).unwrap(),
            ),
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiVPNv4u, true, true).unwrap(),
            ),
            BgpCapability::CapAddPath(
                BgpCapAddPath::new_from_cap(BgpCapability::SafiVPNv6u, true, true).unwrap(),
            ),
            */
        ]
    }
    pub async fn start_updates(&mut self) {
        if let Some(_) = self.updater {
            return;
        }
        let (tx, rx) = channel(100);
        self.upd = Some(tx);
        self.updater = Some(self.rib.run(rx));
    }
    pub async fn run_listen(self: Arc<Self>, sockaddr: SocketAddr) -> io::Result<()> {
        let socket = if sockaddr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(sockaddr)?;
        println!("Listening on {}", sockaddr);
        let listener = socket.listen(1)?;
        loop {
            let client = match listener.accept().await {
                Ok(acc) => acc,
                Err(e) => return Err(e),
            };
            println!("Incoming connected from {}", client.1);
            let fpeer: Arc<ProtoPeer> = match self.config.peers.iter().find(|p| {
                if p.mode == PeerMode::BgpPassive || p.mode == PeerMode::BmpPassive {
                    if let Some(sa) = p.protolisten {
                        if sa == sockaddr {
                            return true;
                        }
                    }
                };
                false
            }) {
                Some(x) => x.clone(),
                None => {
                    eprintln!(
                        "Could not found matching peer for {} @{}",
                        client.1, sockaddr
                    );
                    continue;
                }
            };
            match fpeer.mode {
                PeerMode::BmpPassive => {
                    let mut peer = BmpPeer::new(client.0, fpeer, &*self);
                    peer.lifecycle(self.cancellation.clone()).await;
                    peer.close().await;
                }
                PeerMode::BgpPassive => {
                    let mut peer = BgpPeer::new(
                        BgpSessionParams::new(
                            fpeer.bgppeeras,
                            180,
                            if client.1.is_ipv4() {
                                BgpTransportMode::IPv4
                            } else {
                                BgpTransportMode::IPv6
                            },
                            fpeer.routerid,
                            Self::def_caps(fpeer.bgppeeras),
                        ),
                        client.0,
                        &*self,
                    );
                    let mut scs: bool = true;
                    if let Err(e) = peer.start_passive().await {
                        eprintln!("failed to create BGP peer; err = {:?}", e);
                        scs = false;
                    }
                    if scs {
                        peer.lifecycle(self.cancellation.clone()).await;
                        println!("Session done {}", client.1);
                    };
                    peer.close().await;
                }
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    pub async fn run_peer_active(self: Arc<Self>, fpeer: Arc<ProtoPeer>) -> io::Result<()> {
        let peeraddr = match fpeer.peer {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No peer parameter",
                ))
            }
            Some(l) => l,
        };
        println!("Connecting to {}", peeraddr);
        let peertcp = match tokio::net::TcpStream::connect(peeraddr).await {
            Err(e) => {
                return Err(e);
            }
            Ok(c) => c,
        };
        println!("Connected to {}", peeraddr);
        match fpeer.mode {
            PeerMode::BmpActive => {
                let mut peer = BmpPeer::new(peertcp, fpeer, &*self);
                peer.lifecycle(self.cancellation.clone()).await;
                peer.close().await;
            }
            PeerMode::BgpActive => {
                let mut peer = BgpPeer::new(
                    BgpSessionParams::new(
                        fpeer.bgppeeras,
                        180,
                        match peeraddr {
                            SocketAddr::V4(_) => BgpTransportMode::IPv4,
                            SocketAddr::V6(_) => BgpTransportMode::IPv6,
                        },
                        fpeer.routerid,
                        Self::def_caps(fpeer.bgppeeras),
                    ),
                    peertcp,
                    &*self,
                );
                let mut scs: bool = true;
                if let Err(e) = peer.start_active().await {
                    eprintln!("failed to create BGP peer; err = {:?}", e);
                    scs = false;
                }
                if scs {
                    peer.lifecycle(self.cancellation.clone()).await;
                    println!("Session done {}", peeraddr);
                };
                peer.close().await;
            }
            _ => {}
        }
        Ok(())
    }
    pub async fn run(self: Arc<Self>) {
        let mut lstns: BTreeSet<SocketAddr> = BTreeSet::new();
        for p in self.config.peers.iter() {
            if p.mode == PeerMode::BgpPassive || p.mode == PeerMode::BmpPassive {
                if let Some(sa) = p.protolisten {
                    lstns.insert(sa);
                }
            }
        }
        for sa in lstns.into_iter() {
            let _slf = self.clone();
            tokio::spawn(async move {
                //slf.run_listen(sa).await;
                let canceltok = _slf.cancellation.clone();
                let slf1 = _slf.clone();
                loop {
                    let slf = slf1.clone();
                    select! {
                        _ = canceltok.cancelled() => {
                            return;
                        }
                        _ = slf.run_listen(sa) => {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }
        for p in self.config.peers.iter() {
            if p.mode == PeerMode::BgpActive || p.mode == PeerMode::BmpActive {
                let _slf = self.clone();
                let _p = p.clone();
                tokio::spawn(async move {
                    let canceltok = _slf.cancellation.clone();
                    let slf1 = _slf.clone();
                    loop {
                        let slf = slf1.clone();
                        select! {
                              _ = canceltok.cancelled() => {
                                return;
                              }
                            _ = slf.run_peer_active(_p.clone()) => {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                });
            }
        }
    }
    pub async fn close(mut self) {
        if let Some(ref mut upd) = self.upd {
            if let Err(e) = upd.send(None).await {
                eprintln!("Sending close error: {:?}", e);
                return;
            }
        }
        if let Some(u) = self.updater {
            if let Err(e) = u.join() {
                eprintln!("Joining update task error: {:?}", e);
            }
        }
        self.upd = None;
        self.updater = None;
    }
    pub async fn say_sessions(&self) -> Result<Response<Body>, hyper::http::Error> {
        let sess = match timeout(std::time::Duration::new(5, 0), self.sessions.read()).await {
            Ok(r) => r,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::from_u16(408).unwrap())
                    .header("Content-type", "text/plain")
                    .body("Operation timed out".into());
            }
        };
        match serde_json::to_vec(&*sess) {
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
    pub async fn handle_query(
        &self,
        req: &Request<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let requri = req.uri().path();
        let urlparts: Vec<&str> = requri.split('/').collect();
        if urlparts.len() < 3 {
            return Ok(not_found());
        }
        if urlparts[1] != "api" {
            return Ok(not_found());
        }
        match urlparts[2] {
            "statistics" => return self.rib.say_statistics().await,
            "sessions" => return self.say_sessions().await,
            "json" => {
                if urlparts.len() < 4 {
                    return Ok(not_found());
                } else {
                    return self.rib.say_jsonrib(urlparts[3], req).await;
                }
            }
            _ => return Ok(not_found()),
        };
    }
    pub async fn response_fn(&self, req: &Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match self.handle_query(req).await {
            Ok(v) => Ok(v),
            Err(e) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(format!("BgpSvc error: {:?}", e).into())
                .unwrap()),
        }
    }
}

pub struct RibItems<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> {
    ribsafi: &'a BgpRIBSafi<T>,
    filter: &'a ribfilter::RouteFilter,
    params: RibResponseParams,
}

impl<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> RibItems<'a, T> {
    pub fn count(&self) -> usize {
        if self.filter.terms.len() < 1 {
            self.ribsafi.items.len()
        } else {
            //self.hashmap.iter().filter(|p|{!(self.filter.match_route(p.0, p.1) != ribfilter::FilterItemMatchResult::Yes)}).count()
            self.filter
                .iter_nets(self.ribsafi, self.params.maxdepth, self.params.onlyactive)
                .count()
        }
    }
}

impl<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> serde::Serialize
    for RibItems<'a, T>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(self.params.limit))?;
        let mut cnt: usize = 0;
        for (k, v) in self
            .filter
            .iter_nets(self.ribsafi, self.params.maxdepth, self.params.onlyactive)
            .skip(self.params.skip)
            .take(self.params.limit)
        {
            state.serialize_entry(&k.to_string(), &v)?;
            cnt += 1;
        }
        if cnt < 1 {
            for (k, v) in ribfilter::SortIter::new(
                &mut self.filter.iter_super_nets(
                    self.ribsafi,
                    self.params.maxdepth,
                    self.params.onlyactive,
                ),
                &|a, b| {
                    let alen = a.0.len();
                    let blen = b.0.len();
                    if alen > blen {
                        std::cmp::Ordering::Greater
                    } else if alen < blen {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                },
            )
            .skip(self.params.skip)
            .take(self.params.limit)
            {
                state.serialize_entry(&k.to_string(), &v)?;
                cnt += 1;
            }
        }
        state.end()
    }
}

pub struct RibResponse<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> {
    pub ribtype: String,
    pub length: usize,
    params: RibResponseParams,
    pub items: RibItems<'a, T>,
}
impl<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> RibResponse<'a, T> {
    pub fn new(
        rib: &'a BgpRIBSafi<T>,
        flt: &'a ribfilter::RouteFilter,
        params: RibResponseParams,
    ) -> RibResponse<'a, T> {
        RibResponse::<'a, T> {
            ribtype: std::any::type_name::<T>().to_string(),
            length: rib.items.len(),
            params: params.clone(),
            items: RibItems::<'a, T> {
                ribsafi: rib,
                filter: flt,
                params: params,
            },
        }
    }
}
impl<'a, T: ribfilter::FilterMatchRoute + BgpRIBKey + std::string::ToString> serde::Serialize
    for RibResponse<'a, T>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RibResponse", 8)?;
        state.serialize_field("ribtype", &self.ribtype)?;
        state.serialize_field("length", &self.length)?;
        state.serialize_field("skip", &self.params.skip)?;
        state.serialize_field("limit", &self.params.limit)?;
        state.serialize_field("maxdepth", &self.params.maxdepth)?;
        state.serialize_field("onlyactive", &self.params.onlyactive)?;
        state.serialize_field("found", &self.items.count())?;
        state.serialize_field("items", &self.items)?;
        state.end()
    }
}

impl serde::Serialize for BgpPeerDesc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpPeerDesc", 2)?;
        state.serialize_field("addr", &self.addr)?;
        state.serialize_field("as_num", &self.bom.as_num)?;
        state.end()
    }
}

impl serde::Serialize for BgpSessionDesc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpSessionDesc", 2)?;
        state.serialize_field("peer1", &self.peer1)?;
        state.serialize_field("peer2", &self.peer2)?;
        state.end()
    }
}

impl serde::Serialize for BgpSessionStorage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(self.ss_ids.len()))?;
        for (k, v) in self.ss_ids.iter() {
            let bssd: &BgpSessionDesc = v;
            state.serialize_entry(k, bssd)?;
        }
        state.end()
    }
}
