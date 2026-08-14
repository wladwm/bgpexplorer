use super::Storage;
use crate::bgpattrs::BgpAttrs;
use crate::bgprib::BgpRIBKey;
use crate::bgpsvc::{BgpSessionDesc, BgpSessionId};
use crate::timestamp::Timestamp;
use async_trait::async_trait;
use futures::{stream, StreamExt};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use zettabgp::prelude::{BgpAddrs, WithPathId};

pub struct TextWriter {
    pub prefix: String,
    pub sessions: std::sync::RwLock<BTreeMap<(IpAddr, IpAddr), BgpSessionId>>,
    pub sids: std::sync::RwLock<BTreeMap<BgpSessionId, (IpAddr, IpAddr)>>,
    pub files: tokio::sync::RwLock<
        BTreeMap<(BgpSessionId, &'static str), Arc<tokio::sync::RwLock<BufWriter<File>>>>,
    >,
}
impl TextWriter {
    pub fn new(prefix: String) -> TextWriter {
        TextWriter {
            prefix,
            sessions: std::sync::RwLock::new(BTreeMap::new()),
            sids: std::sync::RwLock::new(BTreeMap::new()),
            files: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }
    fn reg_session(&self, sess: Arc<BgpSessionDesc>, offer: BgpSessionId) -> BgpSessionId {
        let a1 = sess.peer1.addr;
        let a2 = sess.peer2.addr;
        let k = if a1 < a2 { (a1, a2) } else { (a2, a1) };
        if let Some(bid) = self.sessions.read().unwrap().get(&k).cloned() {
            return bid;
        }
        let mut wg = self.sessions.write().unwrap();
        (*wg).insert(k.clone(), offer);
        self.sids.write().unwrap().insert(offer, k);
        offer
    }
    async fn get_out(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
    ) -> Result<Arc<tokio::sync::RwLock<BufWriter<File>>>, std::io::Error> {
        if let Some(f) = self.files.read().await.get(&(session, ribtype)).cloned() {
            return Ok(f);
        }
        let mut wg = self.files.write().await;
        if let Some(f) = wg.get(&(session, ribtype)).cloned() {
            return Ok(f);
        }
        let ss = match self.sids.read().unwrap().get(&session) {
            Some(q) => q.clone(),
            None => return Err(std::io::Error::other("invalid session id")),
        };
        let flnm = format!("{}{}_{}_{}.txt", self.prefix, ribtype, ss.0, ss.1);
        let f = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(flnm)
            .await?;
        let rf = Arc::new(tokio::sync::RwLock::new(BufWriter::new(f)));
        wg.insert((session, ribtype), rf.clone());
        Ok(rf)
    }
    async fn out_upd<T: BgpRIBKey + Display>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let wf = self.get_out(ribtype, session).await?;
        let mut buf = bytes::BytesMut::new();
        for q in v.iter() {
            writeln!(&mut buf, "{}\t+\t{}\t{}", when, q, rattr)?;
        }
        wf.write().await.write_all(&buf).await?;
        Ok(())
    }
    async fn out_upd_path<T: BgpRIBKey + Display>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &[WithPathId<T>],
    ) -> anyhow::Result<()> {
        let wf = self.get_out(ribtype, session).await?;
        let mut buf = bytes::BytesMut::new();
        for q in v.iter() {
            writeln!(&mut buf, "{}\t+\t{}\t{}", when, q, rattr)?;
        }
        wf.write().await.write_all(&buf).await?;
        Ok(())
    }
    async fn out_wdr<T: BgpRIBKey + Display>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let wf = self.get_out(ribtype, session).await?;
        let mut buf = bytes::BytesMut::new();
        for q in v.iter() {
            writeln!(&mut buf, "{}\t-\t{}", when, q)?;
        }
        wf.write().await.write_all(&buf).await?;
        Ok(())
    }
    async fn out_wdr_path<T: BgpRIBKey + Display>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        v: &[WithPathId<T>],
    ) -> anyhow::Result<()> {
        let wf = self.get_out(ribtype, session).await?;
        let mut buf = bytes::BytesMut::new();
        for q in v.iter() {
            writeln!(&mut buf, "{}\t-\t{}", when, q)?;
        }
        wf.write().await.write_all(&buf).await?;
        Ok(())
    }
}

#[async_trait]
impl Storage for TextWriter {
    async fn open(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn shutdown(&self) -> anyhow::Result<()> {
        let mut files = BTreeMap::new();
        {
            let mut wg = self.files.write().await;
            std::mem::swap(&mut (*wg), &mut files);
        }
        stream::iter(files.into_values())
            .for_each(|wa| async move {
                let b = match Arc::into_inner(wa) {
                    Some(q) => q,
                    None => return,
                }
                .into_inner();
                let mut f = b.into_inner();
                let _ = f.shutdown().await;
            })
            .await;
        Ok(())
    }
    async fn register_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId> {
        Ok(self.reg_session(sess, offer))
    }
    async fn store_update(
        &self,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        addrs: &BgpAddrs,
    ) -> anyhow::Result<()> {
        use crate::BgpRibKind;
        match addrs {
            BgpAddrs::IPV4U(v) => {
                self.out_upd(BgpRibKind::RIB_IPV4U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4M(v) => {
                self.out_upd(BgpRibKind::RIB_IPV4M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4LU(v) => {
                self.out_upd(BgpRibKind::RIB_IPV4LU, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV4U(v) => {
                self.out_upd(BgpRibKind::RIB_VPNV4U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV4M(v) => {
                self.out_upd(BgpRibKind::RIB_VPNV4M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV6U(v) => {
                self.out_upd(BgpRibKind::RIB_IPV6U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV6LU(v) => {
                self.out_upd(BgpRibKind::RIB_IPV6LU, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV6U(v) => {
                self.out_upd(BgpRibKind::RIB_VPNV6U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV6M(v) => {
                self.out_upd(BgpRibKind::RIB_VPNV6M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::L2VPLS(v) => {
                self.out_upd(BgpRibKind::RIB_L2VPLS, session, rattr, when, v)
                    .await
            }
            BgpAddrs::MVPN(v) => {
                self.out_upd(BgpRibKind::RIB_MVPN, session, rattr, when, v)
                    .await
            }
            BgpAddrs::EVPN(v) => {
                self.out_upd(BgpRibKind::RIB_EVPN, session, rattr, when, v)
                    .await
            }
            BgpAddrs::FS4U(v) => {
                self.out_upd(BgpRibKind::RIB_FS4U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4UP(v) => {
                self.out_upd_path(BgpRibKind::RIB_IPV4U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4MP(v) => {
                self.out_upd_path(BgpRibKind::RIB_IPV4M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4LUP(v) => {
                self.out_upd_path(BgpRibKind::RIB_IPV4LU, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV4UP(v) => {
                self.out_upd_path(BgpRibKind::RIB_VPNV4U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV4MP(v) => {
                self.out_upd_path(BgpRibKind::RIB_VPNV4M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV6UP(v) => {
                self.out_upd_path(BgpRibKind::RIB_IPV6U, session, rattr, when, v)
                    .await
            }
            //BgpAddrs::IPV6MP(v) => self.ipv6m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV6LUP(v) => {
                self.out_upd_path(BgpRibKind::RIB_IPV6U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV6UP(v) => {
                self.out_upd_path(BgpRibKind::RIB_VPNV6U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::VPNV6MP(v) => {
                self.out_upd_path(BgpRibKind::RIB_VPNV6M, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV4MDT(v) => {
                self.out_upd(BgpRibKind::RIB_IPV4MDT, session, rattr, when, v)
                    .await
            }
            BgpAddrs::IPV6MDT(v) => {
                self.out_upd(BgpRibKind::RIB_IPV6MDT, session, rattr, when, v)
                    .await
            }
            _ => Ok(()),
        }
    }
    async fn store_withdraw(
        &self,
        session: BgpSessionId,
        when: Timestamp,
        addrs: &BgpAddrs,
    ) -> anyhow::Result<()> {
        use crate::BgpRibKind;
        match addrs {
            BgpAddrs::IPV4U(v) => self.out_wdr(BgpRibKind::RIB_IPV4U, session, when, v).await,
            BgpAddrs::IPV4M(v) => self.out_wdr(BgpRibKind::RIB_IPV4M, session, when, v).await,
            BgpAddrs::IPV4LU(v) => self.out_wdr(BgpRibKind::RIB_IPV4LU, session, when, v).await,
            BgpAddrs::VPNV4U(v) => self.out_wdr(BgpRibKind::RIB_VPNV4U, session, when, v).await,
            BgpAddrs::VPNV4M(v) => self.out_wdr(BgpRibKind::RIB_VPNV4M, session, when, v).await,
            BgpAddrs::IPV6U(v) => self.out_wdr(BgpRibKind::RIB_IPV6U, session, when, v).await,
            BgpAddrs::IPV6LU(v) => self.out_wdr(BgpRibKind::RIB_IPV6LU, session, when, v).await,
            BgpAddrs::VPNV6U(v) => self.out_wdr(BgpRibKind::RIB_VPNV6U, session, when, v).await,
            BgpAddrs::VPNV6M(v) => self.out_wdr(BgpRibKind::RIB_VPNV6M, session, when, v).await,
            BgpAddrs::L2VPLS(v) => self.out_wdr(BgpRibKind::RIB_L2VPLS, session, when, v).await,
            BgpAddrs::MVPN(v) => self.out_wdr(BgpRibKind::RIB_MVPN, session, when, v).await,
            BgpAddrs::EVPN(v) => self.out_wdr(BgpRibKind::RIB_EVPN, session, when, v).await,
            BgpAddrs::FS4U(v) => self.out_wdr(BgpRibKind::RIB_FS4U, session, when, v).await,
            BgpAddrs::IPV4UP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_IPV4U, session, when, v)
                    .await
            }
            BgpAddrs::IPV4MP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_IPV4M, session, when, v)
                    .await
            }
            BgpAddrs::IPV4LUP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_IPV4LU, session, when, v)
                    .await
            }
            BgpAddrs::VPNV4UP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_VPNV4U, session, when, v)
                    .await
            }
            BgpAddrs::VPNV4MP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_VPNV4M, session, when, v)
                    .await
            }
            BgpAddrs::IPV6UP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_IPV6U, session, when, v)
                    .await
            }
            //BgpAddrs::IPV6MP(v) => self.ipv6m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV6LUP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_IPV6U, session, when, v)
                    .await
            }
            BgpAddrs::VPNV6UP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_VPNV6U, session, when, v)
                    .await
            }
            BgpAddrs::VPNV6MP(v) => {
                self.out_wdr_path(BgpRibKind::RIB_VPNV6M, session, when, v)
                    .await
            }
            BgpAddrs::IPV4MDT(v) => {
                self.out_wdr(BgpRibKind::RIB_IPV4MDT, session, when, v)
                    .await
            }
            BgpAddrs::IPV6MDT(v) => {
                self.out_wdr(BgpRibKind::RIB_IPV6MDT, session, when, v)
                    .await
            }
            _ => Ok(()),
        }
    }
}
