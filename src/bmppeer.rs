use crate::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zettabgp::bmp::prelude::*;
use zettabgp::prelude::*;

pub struct BmpPeer<'a, H: BgpUpdateHandler> {
    peersock: tokio::net::TcpStream,
    peer: Arc<ProtoPeer>,
    sess: BMPSession,
    sessids: BTreeMap<BgpSessionKey, BgpSessionId>,
    update_handler: &'a H,
}

impl<'a, H: BgpUpdateHandler> BmpPeer<'a, H> {
    pub fn new(
        sock: tokio::net::TcpStream,
        peer: Arc<ProtoPeer>,
        handler: &'a H,
    ) -> BmpPeer<'a, H> {
        BmpPeer {
            peersock: sock,
            peer: peer,
            sess: Default::default(),
            sessids: BTreeMap::new(),
            update_handler: handler,
        }
    }
    pub async fn processmsg(&mut self, msg: BmpMessage) -> Result<(), BgpError> {
        match msg {
            BmpMessage::PeerUpNotification(pu) => {
                if let Some(ref filter_rd) = self.peer.flt_rd {
                    if pu.peer.peerdistinguisher != *filter_rd {
                        //skip non-interesting update
                        //eprintln!("Skip: {:?}", pu);
                        return Ok(());
                    }
                };
                let sessid = self
                    .update_handler
                    .register_session(Arc::new(BgpSessionDesc::from_bmppeerup(&pu)))
                    .await;
                info!(
                    "Register session id {} for peer {:?}",
                    sessid, pu
                );
                self.sessids.insert(BgpSessionKey::from(&pu.peer), sessid);
            }
            BmpMessage::RouteMonitoring(rm) => {
                let sessid = match self.sessids.get(&BgpSessionKey::from(&rm.peer)) {
                    None => {
                        if let Some(ref filter_rd) = self.peer.flt_rd {
                            if rm.peer.peerdistinguisher == *filter_rd {
                                warn!("Skip update: {:?}",rm);
                            };
                        };
                        return Ok(())
                    },
                    Some(x) => *x,
                };
                self.update_handler.handle_update(sessid, rm.update).await;
            }
            _ => info!("BMP: {:?}", msg),
        };
        Ok(())
    }
    pub async fn lifecycle(&mut self, cancel: tokio_util::sync::CancellationToken) {
        let mut buf = Box::new([0 as u8; 65536]);
        loop {
            select! {
              _ = cancel.cancelled() => {
                  break;
              }
              r = self.peersock.read_exact(&mut buf[0..1]) => {
                  match r {
                      Err(e) => {
                          error!("BMP reading error: {:?}",e);
                          break;
                      }
                      Ok(_) => {
                          if buf[0]!=3 {
                              // protocol error?
                              continue;
                          }
                      }
                  }
              }
            };
            select! {
              _ = cancel.cancelled() => {
                  break;
              }
              r = self.peersock.read_exact(&mut buf[1..5]) => {
                  match r {
                      Err(e) => {
                          error!("BMP reading error: {:?}",e);
                          break;
                      }
                      Ok(_) => {
                      }
                  }
              }
            };
            let bmph = match BmpMessageHeader::decode_from(buf.as_ref()) {
                Err(e) => {
                    error!("BmpMessageHeader decode error: {}", e);
                    continue;
                }
                Ok(v) => v,
            };
            if bmph.0.msglength > 65535 {
                continue;
            }
            select! {
                _ = cancel.cancelled() => {
                    break;
                }
                r = self.peersock.read_exact(&mut buf[0..(bmph.0.msglength-5)]) => {
                    match r {
                        Err(e) => {
                            error!("BMP reading error: {:?}",e);
                            break;
                        }
                        Ok(_) => {
                        }
                    }
                }
            };
            let msg = match self.sess.decode_from(&buf[0..(bmph.0.msglength - 5)]) {
                Err(e) => {
                    warn!("BMP decode error: {:?}", e);
                    continue;
                }
                Ok(m) => m,
            };
            if let Err(e) = self.processmsg(msg).await {
                warn!("BMP process error: {:?}", e);
                break;
            };
        }
    }
    pub async fn close(&mut self) {
        match self.peersock.shutdown().await {
            Ok(_) => {}
            Err(e) => {
                warn!("socket shutdown error: {}", e)
            }
        }
    }
}
