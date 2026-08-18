use super::Storage;
use crate::bgpattrs::BgpAttrs;
use crate::bgprib::BgpRIBKey;
use crate::bgpsvc::{BgpSessionDesc, BgpSessionId};
use crate::timestamp::Timestamp;
use crate::BgpRibKind;
use async_trait::async_trait;
use chrono::{Datelike, Timelike};
use mysql_async::prelude::*;
use mysql_async::TxOpts;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use zettabgp::prelude::{BgpAddrs, WithPathId};

pub struct MysqlStorage {
    instance_id: String,
    sessions: tokio::sync::RwLock<BTreeMap<(IpAddr, IpAddr), BgpSessionId>>,
    sids: std::sync::RwLock<BTreeMap<BgpSessionId, (IpAddr, IpAddr)>>,
    pool: mysql_async::Pool,
}

//flag: 0-RD;1-Labels;2-PMSI
const RIB_FLAGS: [(&'static str, u8); 16] = [
    (BgpRibKind::RIB_IPV4U, 0),
    (BgpRibKind::RIB_IPV4M, 0),
    (BgpRibKind::RIB_IPV4LU, 1),
    (BgpRibKind::RIB_VPNV4U, 3),
    (BgpRibKind::RIB_VPNV4M, 3),
    (BgpRibKind::RIB_IPV6U, 0),
    (BgpRibKind::RIB_IPV6LU, 1),
    (BgpRibKind::RIB_VPNV6U, 3),
    (BgpRibKind::RIB_VPNV6M, 3),
    (BgpRibKind::RIB_L2VPLS, 3),
    (BgpRibKind::RIB_MVPN, 7),
    (BgpRibKind::RIB_EVPN, 3),
    (BgpRibKind::RIB_FS4U, 0),
    (BgpRibKind::RIB_FS6U, 0),
    (BgpRibKind::RIB_IPV4MDT, 0),
    (BgpRibKind::RIB_IPV6MDT, 0),
];
/*

create database bgp default character set utf8mb4;
use bgp;
CREATE TABLE if not exists sessions (
     id int(11) NOT NULL AUTO_INCREMENT,
     instance varchar(80),
     peer1 varchar(80),
     peer2 varchar(80),
);
CREATE TABLE if not exists bgprib_ipv4u (
When timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
SessionId int(11) NOT NULL references sessions(id),
//RD UInt64,
Route varchar(255),
PathId int,
Active tinyint,
Origin null varchar(3),
Nexthop null varchar(80),
Aspath null varchar(255),
Comms null jsonb,
LargeComms null jsonb,
ExtComms null jsonb,
Med null int,
Localpref null int,
AtomicAgg null varchar(80),
AggAs null varchar(80),
Originator  null varchar(80),
ClusterList  Array(String),
//Pmsi_ta  null varchar(80),
primary key (When,SessionId,Route,PathId)
);

drop table bgprib_evpn;
drop table bgprib_fs4u;
drop table bgprib_ipv4lu;
drop table bgprib_ipv4m;
drop table bgprib_ipv4mdt;
drop table bgprib_ipv4u;
drop table bgprib_ipv6lu;
drop table bgprib_ipv6mdt;
drop table bgprib_ipv6u;
drop table bgprib_l2vpls;
drop table bgprib_mvpn;
drop table bgprib_vpnv4m;
drop table bgprib_vpnv4u;
drop table bgprib_vpnv6m;
drop table bgprib_vpnv6u;

*/
impl MysqlStorage {
    pub async fn new(instance_id: String, pool: mysql_async::Pool) -> anyhow::Result<MysqlStorage> {
        Ok(MysqlStorage {
            instance_id,
            pool,
            sessions: tokio::sync::RwLock::new(BTreeMap::new()),
            sids: std::sync::RwLock::new(BTreeMap::new()),
        })
    }
    fn deftx(&self) -> TxOpts {
        TxOpts::default()
    }
    async fn reg_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId> {
        let a1 = sess.peer1.addr;
        let a2 = sess.peer2.addr;
        let k = if a1 < a2 { (a1, a2) } else { (a2, a1) };
        if let Some(bid) = self.sessions.read().await.get(&k).cloned() {
            return Ok(bid);
        }
        let mut wg = self.sessions.write().await;
        if let Some(bid) = wg.get(&k).cloned() {
            return Ok(bid);
        }
        let mut con = self.pool.get_conn().await?;
        let p1 = a1.to_string();
        let p2 = a2.to_string();
        let lid = con
            .exec_fold(
                "select id from sessions where instance=? and peer1=? and peer2=?",
                (&self.instance_id, &p1, &p2),
                0u32,
                |df, q| u32::max(df, q),
            )
            .await?;
        if lid > 0 {
            let q = lid as BgpSessionId;
            (*wg).insert(k.clone(), q);
            self.sids.write().unwrap().insert(q, k);
            return Ok(q);
        }
        let mut tx = con.start_transaction(self.deftx()).await?;
        tx.exec_drop(
            "insert into sessions(instance,peer1,peer2) values (?,?,?)",
            (&self.instance_id, &p1, &p2),
        )
        .await?;
        let lid = match tx.last_insert_id() {
            Some(r) => r,
            None => {
                error!(
                    "Unable to get sessionid for {},{},{}",
                    self.instance_id, p1, p2
                );
                return Ok(offer);
            }
        };
        tx.commit().await?;
        let q = lid as BgpSessionId;
        (*wg).insert(k.clone(), q);
        self.sids.write().unwrap().insert(q, k);
        Ok(q)
    }
    fn wrsql(w: &mut dyn std::fmt::Write, ribtype: &'static str) -> anyhow::Result<u8> {
        let mut flg = 0u8;
        for (k, f) in RIB_FLAGS.iter() {
            if ribtype == *k {
                flg = *f;
                break;
            }
        }
        write!(w, "INSERT INTO bgprib_{} (When,SessionId", ribtype)?;
        if flg & 2 > 0 {
            write!(w, ",RD")?;
        }
        write!(w, ",Route,PathId")?;
        if flg & 1 > 0 {
            write!(w, ",Labels")?;
        }
        write!(w,",Active,Origin,Nexthop,Aspath,Comms,LargeComms,ExtComms,Med,Localpref,AtomicAgg,AggAs,Originator,ClusterList")?;
        if flg & 4 > 0 {
            write!(w, ",Pmsi_ta")?;
        }
        write!(w, ") values (")?;
        let cnt = 17
            + (if flg & 1 > 0 { 1 } else { 0 })
            + (if flg & 2 > 0 { 1 } else { 0 })
            + (if flg & 4 > 0 { 1 } else { 0 });
        for i in 0..cnt {
            if i > 0 {
                write!(w, ",?")?;
            } else {
                write!(w, "?")?;
            }
        }
        write!(w, ")")?;
        Ok(flg)
    }
    fn wrsqlinact(w: &mut dyn std::fmt::Write, ribtype: &'static str) -> anyhow::Result<u8> {
        let mut flg = 0u8;
        for (k, f) in RIB_FLAGS.iter() {
            if ribtype == *k {
                flg = *f;
                break;
            }
        }
        write!(w, "INSERT INTO bgprib_{} (When,SessionId", ribtype)?;
        if flg & 2 > 0 {
            write!(w, ",RD")?;
        }
        write!(w, ",Route,PathId")?;
        write!(w, ",Active) values (")?;
        let cnt = 5 + (if flg & 2 > 0 { 1 } else { 0 });
        for i in 0..cnt {
            if i > 0 {
                write!(w, ",?")?;
            } else {
                write!(w, "?")?;
            }
        }
        write!(w, ")")?;
        Ok(flg)
    }
    fn tomydt(t: &Timestamp) -> mysql_async::Value {
        mysql_async::Value::Date(
            t.year() as u16,
            t.month() as u8,
            t.day() as u8,
            t.hour() as u8,
            t.minute() as u8,
            t.second() as u8,
            0,
        )
    }
    fn push_attrs(v: &mut Vec<mysql_async::Value>, rattr: &BgpAttrs) {
        //Origin,Nexthop,Aspath,Comms,LargeComms,ExtComms,Med,Localpref,AtomicAgg,AggAs,Originator,ClusterList
        //Nexthop null varchar(80),Aspath null varchar(255),Comms null jsonb,LargeComms null jsonb,ExtComms null jsonb,
        //Med null int,Localpref null int,AtomicAgg null varchar(80),AggAs null varchar(80),Originator  null varchar(80),ClusterList  null varchar(200)
        match rattr.origin {
            zettabgp::message::attributes::origin::BgpAttrOrigin::Egp => {
                v.push("e".into());
            }
            zettabgp::message::attributes::origin::BgpAttrOrigin::Igp => {
                v.push("i".into());
            }
            _ => {
                v.push("?".into());
            }
        }
        v.push(rattr.nexthop.to_string().into());
        v.push(rattr.aspath.to_string().into());
        if rattr.comms.value.is_empty() {
            v.push(mysql_async::Value::NULL);
        } else {
            v.push(rattr.comms.to_string().into());
        }
        if rattr.lcomms.value.is_empty() {
            v.push(mysql_async::Value::NULL);
        } else {
            v.push(rattr.lcomms.to_string().into());
        }
        if rattr.extcomms.value.is_empty() {
            v.push(mysql_async::Value::NULL);
        } else {
            v.push(rattr.extcomms.to_string().into());
        }
        if let Some(m) = rattr.med.as_ref() {
            v.push((*m).into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
        if let Some(m) = rattr.localpref.as_ref() {
            v.push((*m).into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
        if let Some(m) = rattr.atomicaggregate.as_ref() {
            v.push(m.to_string().into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
        if let Some(m) = rattr.aggregatoras.as_ref() {
            v.push(m.to_string().into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
        if let Some(m) = rattr.originator.as_ref() {
            v.push(m.to_string().into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
        if let Some(m) = rattr.clusterlist.as_ref() {
            v.push(m.to_string().into());
        } else {
            v.push(mysql_async::Value::NULL);
        }
    }
    async fn out_upd<T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let mut buf = bytes::BytesMut::new();
        let flg = Self::wrsql(&mut buf, ribtype)?;
        let mut con = self.pool.get_conn().await?;
        let mut tx = con.start_transaction(self.deftx()).await?;
        tx.exec_batch(
            String::from_utf8_lossy(&buf),
            v.iter().map(|s| {
                let mut v = Vec::<mysql_async::Value>::new();
                v.push(Self::tomydt(&when));
                v.push(session.into());
                if flg & 2 > 0 {
                    match s.getrd() {
                        Some(q) => {
                            v.push(q.to_u64().into());
                        }
                        None => {
                            v.push(mysql_async::Value::NULL);
                        }
                    };
                }
                v.push(s.inner_string().into());
                v.push(0.into());
                if flg & 1 > 0 {
                    match s.getlabels() {
                        Some(l) => {
                            v.push(format!("{}", l).into());
                        }
                        None => v.push(mysql_async::Value::NULL),
                    }
                }
                v.push(1.into());
                Self::push_attrs(&mut v, &rattr);
                if flg & 4 > 0 {
                    if let Some(m) = rattr.pmsi_ta.as_ref() {
                        v.push(m.to_string().into());
                    } else {
                        v.push(mysql_async::Value::NULL);
                    }
                }
                v
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn out_upd_path<
        T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static,
    >(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &[WithPathId<T>],
    ) -> anyhow::Result<()> {
        let mut buf = bytes::BytesMut::new();
        let flg = Self::wrsql(&mut buf, ribtype)?;
        let mut con = self.pool.get_conn().await?;
        let mut tx = con.start_transaction(self.deftx()).await?;
        tx.exec_batch(
            String::from_utf8_lossy(&buf),
            v.iter().map(|s| {
                let mut v = Vec::<mysql_async::Value>::new();
                v.push(Self::tomydt(&when));
                v.push(session.into());
                if flg & 2 > 0 {
                    match s.nlri.getrd() {
                        Some(q) => {
                            v.push(q.to_u64().into());
                        }
                        None => {
                            v.push(mysql_async::Value::NULL);
                        }
                    };
                }
                v.push(s.nlri.inner_string().into());
                v.push(s.pathid.into());
                if flg & 1 > 0 {
                    match s.nlri.getlabels() {
                        Some(l) => {
                            v.push(format!("{}", l).into());
                        }
                        None => v.push(mysql_async::Value::NULL),
                    }
                }
                v.push(1.into());
                Self::push_attrs(&mut v, &rattr);
                if flg & 4 > 0 {
                    if let Some(m) = rattr.pmsi_ta.as_ref() {
                        v.push(m.to_string().into());
                    } else {
                        v.push(mysql_async::Value::NULL);
                    }
                }
                v
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn out_wdr<T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let mut buf = bytes::BytesMut::new();
        let flg = Self::wrsqlinact(&mut buf, ribtype)?;
        let mut con = self.pool.get_conn().await?;
        let mut tx = con.start_transaction(self.deftx()).await?;
        tx.exec_batch(
            String::from_utf8_lossy(&buf),
            v.iter().map(|s| {
                let mut v = Vec::<mysql_async::Value>::new();
                v.push(Self::tomydt(&when));
                v.push(session.into());
                if flg & 2 > 0 {
                    match s.getrd() {
                        Some(q) => {
                            v.push(q.to_u64().into());
                        }
                        None => {
                            v.push(mysql_async::Value::NULL);
                        }
                    };
                }
                v.push(s.inner_string().into());
                v.push(0.into());
                v.push(0.into());
                v
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn out_wdr_path<
        T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static,
    >(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        v: &[WithPathId<T>],
    ) -> anyhow::Result<()> {
        let mut buf = bytes::BytesMut::new();
        let flg = Self::wrsqlinact(&mut buf, ribtype)?;
        let mut con = self.pool.get_conn().await?;
        let mut tx = con.start_transaction(self.deftx()).await?;
        tx.exec_batch(
            String::from_utf8_lossy(&buf),
            v.iter().map(|s| {
                let mut v = Vec::<mysql_async::Value>::new();
                v.push(Self::tomydt(&when));
                v.push(session.into());
                if flg & 2 > 0 {
                    match s.nlri.getrd() {
                        Some(q) => {
                            v.push(q.to_u64().into());
                        }
                        None => {
                            v.push(mysql_async::Value::NULL);
                        }
                    };
                }
                v.push(s.nlri.inner_string().into());
                v.push(s.pathid.into());
                v.push(0.into());
                v
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl Storage for MysqlStorage {
    async fn open(&mut self) -> anyhow::Result<()> {
        let mut con = self.pool.get_conn().await?;
        con.exec_drop("CREATE TABLE if not exists sessions (id int(11) NOT NULL AUTO_INCREMENT,instance varchar(80),peer1 varchar(80),peer2 varchar(80))", ()).await?;
        let mut buf = bytes::BytesMut::new();
        for (rib, flg) in RIB_FLAGS {
            buf.clear();
            write!(
                &mut buf,
                "CREATE TABLE if not exists bgprib_{} (When timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,SessionId int(11) NOT NULL references sessions(id),",
                rib
            )?;
            if flg & 2 > 0 {
                write!(&mut buf, "RD bigint,")?;
            }
            write!(&mut buf, "Route varchar(255),PathId int,")?;
            if flg & 1 > 0 {
                write!(&mut buf, "Labels null jsonb,")?;
            }
            write!(&mut buf,"Active tinyint,Origin null varchar(3),Nexthop null varchar(80),Aspath null varchar(255),Comms null jsonb,LargeComms null jsonb,ExtComms null jsonb,
Med null int,Localpref null int,AtomicAgg null varchar(80),AggAs null varchar(80),Originator  null varchar(80),ClusterList  null varchar(200)")?;
            if flg & 4 > 0 {
                write!(&mut buf, ",Pmsi_ta null varchar(80)")?;
            }
            write!(&mut buf, " primary key (When,SessionId")?;
            if flg & 2 > 0 {
                write!(&mut buf, "RD,")?;
            }
            write!(&mut buf, "Route,PathId))")?;
            con.exec_drop(String::from_utf8_lossy(&buf), ()).await?;
        }
        Ok(())
    }
    async fn shutdown(&self) -> anyhow::Result<()> {
        //self.pool.disconnect()
        Ok(())
    }
    async fn register_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId> {
        self.reg_session(sess, offer).await
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
            BgpAddrs::FS6U(v) => {
                self.out_upd(BgpRibKind::RIB_FS6U, session, rattr, when, v)
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
            BgpAddrs::FS6U(v) => self.out_wdr(BgpRibKind::RIB_FS6U, session, when, v).await,
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
