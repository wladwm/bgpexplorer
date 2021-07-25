use crate::bgpsvc::*;
use chrono::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::*;
use zettabgp::prelude::*;

pub struct BgpPeer<'a, H: BgpUpdateHandler> {
    params: BgpSessionParams,
    peersock: tokio::net::TcpStream,
    keepalive_sent: DateTime<Local>,
    sessionid: BgpSessionId,
    update_handler: &'a H,
}

impl<'a, H: BgpUpdateHandler> BgpPeer<'a, H> {
    pub fn new(
        pars: BgpSessionParams,
        stream: tokio::net::TcpStream,
        handler: &'a H,
    ) -> BgpPeer<'a, H> {
        let peerip = stream.peer_addr().unwrap().ip();
        let mut ret = BgpPeer::<H> {
            params: pars,
            peersock: stream,
            keepalive_sent: Local::now(),
            update_handler: handler,
            sessionid: 0,
        };
        ret.params.peer_mode = if peerip.is_ipv4() {
            BgpTransportMode::IPv4
        } else {
            BgpTransportMode::IPv6
        };
        ret
    }
    async fn read_socket(&mut self, buf: &mut [u8]) -> Result<(), BgpError> {
        match self.peersock.read_exact(buf).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    async fn write_socket(&mut self, buf: &[u8]) -> Result<(), BgpError> {
        match self.peersock.write_all(buf).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    async fn recv_message_head(&mut self) -> Result<(BgpMessageType, usize), BgpError> {
        let mut buf = [0 as u8; 19];
        self.read_socket(&mut buf).await?;
        self.params.decode_message_head(&buf)
    }
    fn get_message_body_ref<'b>(buf: &'b mut [u8]) -> Result<&'b mut [u8], BgpError> {
        if buf.len() < 19 {
            return Err(BgpError::insufficient_buffer_size());
        }
        Ok(&mut buf[19..])
    }
    async fn send_message_buf(
        &mut self,
        buf: &mut [u8],
        messagetype: BgpMessageType,
        messagelen: usize,
    ) -> Result<(), BgpError> {
        let blen = self
            .params
            .prepare_message_buf(buf, messagetype, messagelen)?;
        self.write_socket(&buf[0..blen]).await
    }
    pub async fn start_passive(&mut self) -> Result<(), BgpError> {
        let mut bom = BgpOpenMessage::new();
        let mut buf = [255 as u8; 255];
        let msg = match self.recv_message_head().await {
            Err(e) => return Err(e),
            Ok(msg) => msg,
        };
        if msg.0 != BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid state to start_passive"));
        }
        self.read_socket(&mut buf[0..msg.1]).await?;
        bom.decode_from(&self.params, &buf[0..msg.1])?;
        let remsess = BgpPeerDesc::new(self.peersock.peer_addr().unwrap().ip(), bom.clone());
        bom.router_id = self.params.router_id;
        self.params.as_num = bom.as_num;
        self.params.hold_time = bom.hold_time;
        self.params.match_caps(&bom.caps);
        let sz = match bom.encode_to(&self.params, BgpPeer::<H>::get_message_body_ref(&mut buf)?) {
            Err(e) => return Err(e),
            Ok(sz) => sz,
        };
        self.send_message_buf(&mut buf, BgpMessageType::Open, sz)
            .await?;
        let mysess = BgpPeerDesc::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), bom.clone());
        self.sessionid = self
            .update_handler
            .register_session(Arc::new(BgpSessionDesc::new(mysess, remsess)))
            .await;
        Ok(())
    }
    pub async fn start_active(&mut self) -> Result<(), BgpError> {
        let bom = self.params.open_message();
        let mut buf = [255 as u8; 255];
        let sz = match bom.encode_to(&self.params, BgpPeer::<H>::get_message_body_ref(&mut buf)?) {
            Err(e) => {
                return Err(e);
            }
            Ok(sz) => sz,
        };
        let mysess = BgpPeerDesc::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), bom.clone());
        self.send_message_buf(&mut buf, BgpMessageType::Open, sz)
            .await?;
        let msg = match self.recv_message_head().await {
            Err(e) => {
                return Err(e);
            }
            Ok(msg) => msg,
        };
        if msg.0 != BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid state to start_active"));
        }
        self.read_socket(&mut buf[0..msg.1]).await?;
        let mut bomrcv = self.params.open_message();
        bomrcv.decode_from(&self.params, &buf[0..msg.1])?;
        let remsess = BgpPeerDesc::new(self.peersock.peer_addr().unwrap().ip(), bomrcv.clone());
        self.params.hold_time = bomrcv.hold_time;
        self.params.match_caps(&bomrcv.caps);
        self.sessionid = self
            .update_handler
            .register_session(Arc::new(BgpSessionDesc::new(mysess, remsess)))
            .await;
        Ok(())
    }
    pub async fn send_keepalive(&mut self) -> Result<(), BgpError> {
        let mut buf = [255 as u8; 19];
        let blen = self
            .params
            .prepare_message_buf(&mut buf, BgpMessageType::Keepalive, 0)?;
        match self.write_socket(&buf[0..blen]).await {
            Ok(_) => {
                self.keepalive_sent = Local::now();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    pub async fn lifecycle(&mut self, cancel: tokio_util::sync::CancellationToken) {
        let mut buf = [255 as u8; 4096];
        let keep_interval = chrono::Duration::seconds((self.params.hold_time / 3) as i64);
        loop {
            let mut tosleep = Local::now() - self.keepalive_sent;
            if tosleep >= keep_interval {
                match self.send_keepalive().await {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Keepalive send error: {:?}", e);
                    }
                }
                tosleep = Local::now() - self.keepalive_sent;
            }
            tosleep = keep_interval - tosleep;
            let tosleepstd = match tosleep.to_std() {
                Ok(s) => s,
                Err(_) => std::time::Duration::from_secs(1),
            };
            let msg = select! {
                _ = cancel.cancelled() => {
                    // The token was cancelled
                    break;
                }
                _ = tokio::time::sleep(tosleepstd) => {
                    (BgpMessageType::Keepalive,0)
                }
                msgin = self.recv_message_head() => {
                    match msgin {
                        Err(e) => {
                            eprintln!("recv_message_head: {:?}", e);
                            break;
                        }
                        Ok(msg) => msg
                    }
                }
            };
            if let Err(e) = self.read_socket(&mut buf[0..msg.1]).await {
                eprintln!("recv_message: {:?}", e);
            };
            match msg.0 {
                BgpMessageType::Open => {
                    eprintln!("Incorrect open message!");
                    break;
                }
                BgpMessageType::Keepalive => match self.send_keepalive().await {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Keepalive sending error: {:?}", e);
                    }
                },
                BgpMessageType::Notification => {
                    let mut msgnotification = BgpNotificationMessage::new();
                    match msgnotification.decode_from(&self.params, &buf[0..msg.1]) {
                        Err(e) => {
                            eprintln!("BGP notification decode error: {:?}", e);
                        }
                        Ok(_) => {
                            println!(
                                "BGP notification: {:?} - {:?}",
                                msgnotification,
                                msgnotification.error_text()
                            );
                        }
                    };
                    break;
                }
                BgpMessageType::Update => {
                    let mut msgupdate = BgpUpdateMessage::new();
                    if let Err(e) = msgupdate.decode_from(&self.params, &buf[0..msg.1]) {
                        eprintln!("BGP update decode error: {:?}", e);
                        continue;
                    }
                    self.update_handler
                        .handle_update(self.sessionid, msgupdate)
                        .await;
                }
            }
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
