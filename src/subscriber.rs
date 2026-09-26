use crate::bgpattrs::BgpAttrs;
use crate::bgprib::*;
use crate::bgpsvc::BgpSessionId;
use crate::ribfilter::{FilterItemMatchResult, RouteFilter};
use futures::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::codec::Framed;
use websocket_codec::{Message, MessageCodec};
use zettabgp::prelude::*;
//use serde_json::{Result, Value};
use serde::ser::SerializeStruct;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
struct CmdSubscribe {
    rib: String,
    filter: String,
}
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    Subscribe(CmdSubscribe),
}
struct EventUpdate {
    sessionid: BgpSessionId,
    attrs: Arc<BgpAttrs>,
    addrs: Arc<BgpAddrs>,
}
impl serde::Serialize for EventUpdate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("Update", 3)?;
        map.serialize_field("message", "update")?;
        map.serialize_field("sessionid", &self.sessionid)?;
        map.serialize_field("attrs", self.attrs.as_ref())?;
        map.serialize_field("addrs", self.addrs.as_ref())?;
        map.end()
    }
}
struct EventWithdraw {
    sessionid: BgpSessionId,
    //attrs: Arc<BgpAttrs>,
    addrs: Arc<BgpAddrs>,
}
impl serde::Serialize for EventWithdraw {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("Withdraw", 2)?;
        map.serialize_field("message", "withdraw")?;
        map.serialize_field("sessionid", &self.sessionid)?;
        //map.serialize_field("attrs", self.attrs.as_ref())?;
        map.serialize_field("addrs", self.addrs.as_ref())?;
        map.end()
    }
}
struct EventError {
    text: String,
}
impl serde::Serialize for EventError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("Error", 1)?;
        map.serialize_field("message", "error")?;
        map.serialize_field("text", &self.text)?;
        map.end()
    }
}
fn filter_routes(
    filter: &RouteFilter,
    routes: Arc<zettabgp::afi::BgpAddrs>,
    attrs: &BgpAttrs,
) -> Option<Arc<zettabgp::afi::BgpAddrs>> {
    if filter.is_empty() {
        return Some(routes);
    }
    use zettabgp::afi::BgpAddrs;
    match &*routes {
        BgpAddrs::None => {}
        BgpAddrs::IPV4U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4U(rv)));
        }
        BgpAddrs::IPV4UP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4UP(rv)));
        }
        BgpAddrs::IPV4M(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4M(rv)));
        }
        BgpAddrs::IPV4MP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4MP(rv)));
        }
        BgpAddrs::IPV4LU(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4LU(rv)));
        }
        BgpAddrs::IPV4LUP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4LUP(rv)));
        }
        BgpAddrs::VPNV4U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV4U(rv)));
        }
        BgpAddrs::VPNV4UP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV4UP(rv)));
        }
        BgpAddrs::VPNV4M(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV4M(rv)));
        }
        BgpAddrs::VPNV4MP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV4MP(rv)));
        }
        BgpAddrs::IPV4MDT(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4MDT(rv)));
        }
        BgpAddrs::IPV4MDTP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV4MDTP(rv)));
        }
        BgpAddrs::IPV6U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6U(rv)));
        }
        BgpAddrs::IPV6UP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6UP(rv)));
        }
        BgpAddrs::IPV6M(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6M(rv)));
        }
        BgpAddrs::IPV6MP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6MP(rv)));
        }
        BgpAddrs::IPV6LU(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6LU(rv)));
        }
        BgpAddrs::IPV6LUP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6LUP(rv)));
        }
        BgpAddrs::VPNV6U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV6U(rv)));
        }
        BgpAddrs::VPNV6UP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV6UP(rv)));
        }
        BgpAddrs::VPNV6M(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV6M(rv)));
        }
        BgpAddrs::VPNV6MP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::VPNV6MP(rv)));
        }
        BgpAddrs::IPV6MDT(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6MDT(rv)));
        }
        BgpAddrs::IPV6MDTP(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(&r.nlri, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::IPV6MDTP(rv)));
        }
        BgpAddrs::L2VPLS(_) => {
            return None;
        }
        BgpAddrs::MVPN(_) => {
            return None;
        }
        BgpAddrs::EVPN(_) => {
            return None;
        }
        BgpAddrs::FS4U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::FS4U(rv)));
        }
        BgpAddrs::FSV4U((rd, v)) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::FSV4U((rd.clone(), rv))));
        }
        BgpAddrs::FS6U(v) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::FS6U(rv)));
        }
        BgpAddrs::FSV6U((rd, v)) => {
            let mut rv = Vec::new();
            for r in v.iter() {
                if filter.match_route(r, &attrs) == FilterItemMatchResult::Yes {
                    rv.push(r.clone());
                }
            }
            if rv.is_empty() {
                return None;
            };
            rv.shrink_to_fit();
            return Some(Arc::new(BgpAddrs::FSV6U((rd.clone(), rv))));
        }
    };
    Some(routes)
}
pub async fn on_subscriber_client(
    mut rcv: tokio::sync::broadcast::Receiver<BgpEvent>,
    mut client: Framed<Upgraded, MessageCodec>,
) {
    let mut subs: BTreeMap<BgpRibKind, RouteFilter> = BTreeMap::new();
    lazy_static! {
        static ref EmptyAttrs: BgpAttrs = BgpAttrs::new();
        static ref EmptyFilter: RouteFilter = RouteFilter::new();
    };
    loop {
        tokio::select! {
            evtr = rcv.recv() => {
                match evtr {
                    Err(e) => {
                        error!("BgpEvent receiver got error: {}", e);
                        if let Ok(vl) = serde_json::to_string(&EventError{text:format!("BgpEvent receiver got error: {}", e)}) {
                            let _ = client.send(Message::text(vl)).await;
                        }
                    }
                    Ok(evt) => {
                        match evt {
                            BgpEvent::Update(sessionid, attrs, addrs) => {
                                if let Some(uk) = BgpRibKind::from_bgp_addrs(&addrs) {
                                    if let Some(flt)=subs.get(&uk).or_else(|| if subs.is_empty() {Some(&EmptyFilter)} else {None}) {
                                        if let Some(ret) = filter_routes(flt,addrs,&*attrs) {
                                            if let Ok(vl) = serde_json::to_string(&EventUpdate{sessionid,attrs,addrs: ret}) {
                                                    let _ = client.send(Message::text(vl)).await;
                                                }
                                            }
                                    }
                                }
                            }
                            BgpEvent::Withdraw(sessionid, addrs) => {
                                if let Some(uk) = BgpRibKind::from_bgp_addrs(&addrs) {
                                    if let Some(flt)=subs.get(&uk).or_else(|| if subs.is_empty() {Some(&EmptyFilter)} else {None}) {
                                        if let Some(ret) = filter_routes(flt,addrs,&EmptyAttrs) {
                                          if let Ok(vl) = serde_json::to_string(&EventWithdraw{sessionid,addrs: ret}) {
                                            let _ = client.send(Message::text(vl)).await;
                                          }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            inmsgo = client.next() => {
                match inmsgo {
                    None => {
                        info!("Websocket received none");
                        return;
                    }
                    Some(inmsgr)=> match inmsgr {
                        Err(e) => {
                            info!("Websocket received error: {}", e);
                            return;
                        }
                        Ok(inmsg) => {
                            info!("Got websocket: {:?}", inmsg);
                            match inmsg.opcode() {
                                websocket_codec::Opcode::Ping => {
                                    let _ = client.send(Message::pong(inmsg.into_data())).await;
                                }
                                websocket_codec::Opcode::Pong => {}
                                websocket_codec::Opcode::Close => {break;}
                                websocket_codec::Opcode::Text | websocket_codec::Opcode::Binary => {
                                    if let Some(s) = inmsg.as_text() {
                                        let cc: ClientCmd = match serde_json::from_str(s) {
                                            Err(e) => {warn!("Websocket deserialize error: {}",e);continue;}
                                            Ok(c) => c
                                        };
                                        match cc {
                                            ClientCmd::Subscribe(cs) => {
                                                if let Ok(rib) = cs.rib.parse() {
                                                    let mut flt = RouteFilter::new();
                                                    flt.parse(cs.filter.as_str());
                                                    subs.insert(rib, flt);
                                                }
                                            }
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
