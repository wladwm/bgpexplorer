use crate::bgpsvc::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::*;
use zettabgp::bmp::prelude::*;
use zettabgp::prelude::*;

pub struct BmpPeer<'a, H: BgpUpdateHandler> {
    peersock: tokio::net::TcpStream,
    filterpeer: Option<std::net::IpAddr>,
    update_handler: &'a H,
}

impl<'a, H: BgpUpdateHandler> BmpPeer<'a, H> {
    pub fn new(
        sock: tokio::net::TcpStream,
        flt: Option<std::net::IpAddr>,
        handler: &'a H,
    ) -> BmpPeer<'a, H> {
        BmpPeer {
            peersock: sock,
            filterpeer: flt,
            update_handler: handler,
        }
    }
    pub async fn processmsg(&mut self, msg: BmpMessage) -> Result<(), BgpError> {
        if let BmpMessage::RouteMonitoring(rm) = msg {
            if let Some(filter) = self.filterpeer {
                if filter != rm.peer.peeraddress {
                    //skip non-interesting update
                    return Ok(());
                }
            } else {
                // filter first peer
                self.filterpeer = Some(rm.peer.peeraddress.clone())
            }
            self.update_handler.handle_update(rm.update).await
        } else {
            eprintln!("BMP: {:?}", msg);
        }
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
                          eprintln!("BMP reading error: {:?}",e);
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
                          eprintln!("BMP reading error: {:?}",e);
                          break;
                      }
                      Ok(_) => {
                      }
                  }
              }
            };
            let bmph = match BmpMessageHeader::decode_from(buf.as_ref()) {
                Err(e) => {
                    eprintln!("BmpMessageHeader decode error: {}", e);
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
                            eprintln!("BMP reading error: {:?}",e);
                            break;
                        }
                        Ok(_) => {
                        }
                    }
                }
            };
            let msg = match BmpMessage::decode_from(&buf[0..(bmph.0.msglength - 5)]) {
                Err(e) => {
                    eprintln!("BMP decode error: {:?}", e);
                    continue;
                }
                Ok(m) => m,
            };
            if let Err(e) = self.processmsg(msg).await {
                eprintln!("BMP process error: {:?}", e);
                break;
            };
        }
    }
    pub async fn close(&mut self) {
        match self.peersock.shutdown().await {
            Ok(_) => {}
            Err(e) => {
                println!("Warning: socket shutdown error: {}", e)
            }
        }
    }
}
