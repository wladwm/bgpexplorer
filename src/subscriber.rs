use crate::bgpattrs::BgpAttrs;
use crate::bgprib::*;
use crate::bgpsvc::BgpSessionId;
use crate::ribfilter::RouteFilter;
use futures::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::codec::Framed;
use websocket_codec::{Message, MessageCodec};
use zettabgp::prelude::*;
//use serde_json::{Result, Value};
use serde::ser::SerializeStruct;

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
        map.serialize_field("sessionid", &self.sessionid)?;
        //map.serialize_field("attrs", self.attrs.as_ref())?;
        map.serialize_field("addrs", self.addrs.as_ref())?;
        map.end()
    }
}
pub async fn on_subscriber_client(
    mut rcv: tokio::sync::broadcast::Receiver<BgpEvent>,
    mut client: Framed<Upgraded, MessageCodec>,
) {
    let mut rib: BgpRibKind = BgpRibKind::IpV4u;
    let mut filter = RouteFilter::new();
    loop {
        tokio::select! {
            evtr = rcv.recv() => {
                match evtr {
                    Err(e) => {
                        error!("Websocket client got error: {}", e);
                        let _ = client.send(Message::close(None)).await;
                        return
                    }
                    Ok(evt) => {
                        match evt {
                            BgpEvent::Update(sessionid, attrs, addrs) => {
                                if let Some(uk) = BgpRibKind::from_bgp_addrs(&addrs) {
                                    if uk==rib {
                                        if let Ok(vl) = serde_json::to_string(&EventUpdate{sessionid,attrs,addrs}) {
                                            let _ = client.send(Message::text(vl)).await;
                                        }
                                    }
                                }
                            }
                            BgpEvent::Withdraw(sessionid, addrs) => {
                                if let Some(uk) = BgpRibKind::from_bgp_addrs(&addrs) {
                                    if uk==rib {
                                        if let Ok(vl) = serde_json::to_string(&EventWithdraw{sessionid,addrs}) {
                                            let _ = client.send(Message::text(vl)).await;
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
                                                rib = cs.rib.parse().unwrap_or(rib);
                                                filter.parse(cs.filter.as_str());
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
