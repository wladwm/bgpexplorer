use crate::bgppeer::*;
use crate::bgprib::*;
use crate::bmppeer::*;
use crate::ribservice::*;
use crate::*;
use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use serde::ser::{SerializeMap, SerializeStruct};
use std::net::SocketAddr;
use std::thread::JoinHandle;
use std::vec::Vec;
use tokio::net::TcpSocket;
use tokio::sync::mpsc::*;
use zettabgp::prelude::*;

#[async_trait]
pub trait BgpUpdateHandler {
    async fn handle_update(&self, upd: BgpUpdateMessage);
}

pub struct BgpSvr {
    pub config: SvcConfig,
    pub cancellation: tokio_util::sync::CancellationToken,
    pub rib: BgpRIBts,
    upd: Option<Sender<Option<BgpUpdateMessage>>>,
    updater: Option<JoinHandle<()>>,
}
#[async_trait]
impl BgpUpdateHandler for BgpSvr {
    async fn handle_update(&self, upd: BgpUpdateMessage) {
        match self.upd {
            None => eprintln!("Skip update"),
            Some(ref updch) => match updch.send(Some(upd)).await {
                Ok(_) => {}
                Err(e) => eprintln!("Queued update error: {:?}", e),
            },
        };
    }
}
impl BgpSvr {
    pub fn new(cfg: SvcConfig, cancel_token: tokio_util::sync::CancellationToken) -> BgpSvr {
        BgpSvr {
            config: cfg.clone(),
            cancellation: cancel_token,
            rib: BgpRIBts::new(&cfg),
            upd: None,
            updater: None,
        }
    }
    pub async fn start_updates(&mut self) {
        if let Some(_) = self.updater {
            return;
        }
        let (tx, rx) = channel(100);
        self.upd = Some(tx);
        self.updater = Some(self.rib.run(rx));
    }
    pub async fn runonce_active(&self) -> io::Result<()> {
        let bgppeer = match self.config.bgppeer {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No bgppeer parameter",
                ))
            }
            Some(l) => l,
        };
        println!("BGP trying {}", bgppeer);
        let peertcp = match tokio::net::TcpStream::connect(bgppeer).await {
            Err(e) => {
                return Err(e);
            }
            Ok(c) => c,
        };
        println!("Connected to {}", bgppeer);
        let mut peer = BgpPeer::new(
            BgpSessionParams::new(
                self.config.bgppeeras,
                180,
                match bgppeer {
                    SocketAddr::V4(_) => BgpTransportMode::IPv4,
                    SocketAddr::V6(_) => BgpTransportMode::IPv6,
                },
                self.config.routerid,
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
                    BgpCapability::CapASN32(self.config.bgppeeras),
                ]
                .into_iter()
                .collect(),
            ),
            peertcp,
            self,
        );
        let mut scs: bool = true;
        if let Err(e) = peer.start_active().await {
            eprintln!("failed to create BGP peer; err = {:?}", e);
            scs = false;
        }
        if scs {
            peer.lifecycle(self.cancellation.clone()).await;
            println!("Session done {}", self.config.bgppeeras);
        };
        peer.close().await;
        Ok(())
    }
    pub async fn runonce_passive(&self) -> io::Result<()> {
        let bgplisten = match self.config.protolisten {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No protolisten parameter",
                ))
            }
            Some(l) => l,
        };
        let socket = if bgplisten.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bgplisten)?;
        println!("BGP await connection on {}", bgplisten);
        let listener = socket.listen(1)?;
        let client = match listener.accept().await {
            Ok(acc) => acc,
            Err(e) => return Err(e),
        };
        println!("BGP connected from {}", client.1);
        let mut peer = BgpPeer::new(
            BgpSessionParams::new(
                self.config.bgppeeras,
                180,
                if bgplisten.is_ipv4() {
                    BgpTransportMode::IPv4
                } else {
                    BgpTransportMode::IPv6
                },
                self.config.routerid,
                vec![
                    BgpCapability::SafiIPv4u,
                    BgpCapability::SafiIPv4m,
                    BgpCapability::SafiIPv4lu,
                    BgpCapability::SafiIPv6lu,
                    BgpCapability::SafiVPNv4u,
                    BgpCapability::SafiVPNv4m,
                    BgpCapability::SafiVPNv6u,
                    BgpCapability::SafiVPNv6m,
                    BgpCapability::SafiIPv4mvpn,
                    BgpCapability::SafiVPLS,
                    BgpCapability::SafiEVPN,
                    BgpCapability::SafiIPv4fu,
                    BgpCapability::SafiIPv6fu,
                    BgpCapability::CapASN32(self.config.bgppeeras),
                ]
                .into_iter()
                .collect(),
            ),
            client.0,
            self,
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
        Ok(())
    }
    pub async fn bmp_runonce_passive(&self) -> io::Result<()> {
        let bmplisten = match self.config.protolisten {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No protolisten parameter",
                ))
            }
            Some(l) => l,
        };
        let socket = if bmplisten.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bmplisten)?;
        println!("BMP await connection on {}", bmplisten);
        let listener = socket.listen(1)?;
        let client = match listener.accept().await {
            Ok(acc) => acc,
            Err(e) => return Err(e),
        };
        println!("BMP connected from {}", client.1);
        let mut peer = BmpPeer::new(
            client.0,
            if let Some(bp) = self.config.bgppeer {
                Some(bp.ip())
            } else {
                None
            },
            self,
        );
        peer.lifecycle(self.cancellation.clone()).await;
        peer.close().await;
        Ok(())
    }
    pub async fn bmp_runonce_active(&self) -> io::Result<()> {
        let bmppeer = match self.config.bmppeer {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No bmppeer parameter",
                ))
            }
            Some(l) => l,
        };
        println!("BMP trying {}", bmppeer);
        let peertcp = match tokio::net::TcpStream::connect(bmppeer).await {
            Err(e) => {
                return Err(e);
            }
            Ok(c) => c,
        };
        println!("BMP connected to {}", bmppeer);
        let mut peer = BmpPeer::new(
            peertcp,
            if let Some(bp) = self.config.bgppeer {
                Some(bp.ip())
            } else {
                None
            },
            self,
        );
        peer.lifecycle(self.cancellation.clone()).await;
        peer.close().await;
        Ok(())
    }
    pub async fn run_active(&self) {
        loop {
            select! {
                _ = self.cancellation.cancelled() => {
                    return;
                }
                _ = self.runonce_active() => {
                    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
                }
            }
        }
    }
    pub async fn run_passive(&self) {
        loop {
            select! {
                _ = self.cancellation.cancelled() => {
                    return;
                }
                _ = self.runonce_passive() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
    pub async fn run_bmp_passive(&self) {
        loop {
            select! {
                _ = self.cancellation.cancelled() => {
                    return ;
                }
                _ = self.bmp_runonce_passive() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
    pub async fn run_bmp_active(&self) {
        loop {
            select! {
                _ = self.cancellation.cancelled() => {
                    return;
                }
                _ = self.bmp_runonce_active() => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
    pub async fn run(&self, mode: PeerMode) {
        match mode {
            PeerMode::BgpActive => self.run_active().await,
            PeerMode::BgpPassive => self.run_passive().await,
            PeerMode::BmpPassive => self.run_bmp_passive().await,
            PeerMode::BmpActive => self.run_bmp_active().await,
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
            state.serialize_entry::<std::string::String, BgpAttrHistory>(&k.to_string(), v)?;
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
                state.serialize_entry::<std::string::String, BgpAttrHistory>(&k.to_string(), v)?;
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
