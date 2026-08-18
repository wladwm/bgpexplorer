use super::Storage;
use crate::bgpattrs::BgpAttrs;
use crate::bgprib::BgpRIBKey;
use crate::bgpsvc::{BgpSessionDesc, BgpSessionId};
use crate::timestamp::Timestamp;
use crate::BgpRibKind;
use anyhow::Context;
use async_trait::async_trait;
use futures::task::Poll;
use futures_util::stream::Stream;
use klickhouse::bb8::ManageConnection;
use klickhouse::*;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fmt::Write;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_stream::StreamExt;
use zettabgp::afi::MplsLabels;
use zettabgp::prelude::{BgpAddrs, WithPathId};

#[derive(Clone)]
pub struct ClickhouseStorageOptions {
    pub instance_id: String,
    pub partition_by: String,
    pub table_ttl: String,
    pub break_count: usize,
    pub batch_size: usize,
    pub batch_dur: std::time::Duration,
}
impl std::default::Default for ClickhouseStorageOptions {
    fn default() -> ClickhouseStorageOptions {
        ClickhouseStorageOptions {
            instance_id: "".to_string(),
            partition_by: "toYYYYMM(When)".to_string(),
            table_ttl: "When + INTERVAL 12 MONTH".to_string(),
            break_count: 5,
            batch_size: 1000usize,
            batch_dur: std::time::Duration::from_secs(5),
        }
    }
}

pub struct ClickhouseStorage {
    cso: ClickhouseStorageOptions,
    sessions: tokio::sync::RwLock<BTreeMap<(IpAddr, IpAddr), BgpSessionId>>,
    sids: std::sync::RwLock<BTreeMap<BgpSessionId, (IpAddr, IpAddr)>>,
    click: klickhouse::ConnectionManager,
    upd: tokio::sync::RwLock<BTreeMap<&'static str, InserterChannel<RibRowU>>>,
    wdr: tokio::sync::RwLock<BTreeMap<&'static str, InserterChannel<RibRowW>>>,
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

create database bgp;
use bgp;
CREATE TABLE if not exists sessions (
     id UInt32,
     instance String,
     peer1 String,
     peer2 String,
) Engine=MergeTree() primary key (id) ORDER BY (id);
CREATE TABLE if not exists bgprib_ipv4u (
When DateTime('UTC'),
SessionId UInt32,
//RD UInt64,
Route String,
PathId UInt32,
Active UInt8,
Origin Nullable(String),
Nexthop Nullable(String),
Aspath Nullable(String),
Comms Array(String),
LargeComms Array(String),
ExtComms Array(String),
Med Nullable(UInt32),
Localpref Nullable(UInt32),
AtomicAgg Nullable(String),
AggAs Nullable(String),
Originator  Nullable(String),
ClusterList  Array(String),
Pmsi_ta  Nullable(String)
)
ENGINE = MergeTree() primary key (When,SessionId,Route,PathId) ORDER BY (When,SessionId,Route,PathId) TTL When + INTERVAL 12 MONTH;

drop table bgprib_evpn;
drop table bgprib_fs4u;
drop table bgprib_fs6u;
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
const C_WHEN: &'static str = "When";
const C_SESSION: &'static str = "SessionId";
const C_ACTIVE: &'static str = "Active";
const C_RD: &'static str = "RD";
const C_LABELS: &'static str = "Labels";
const C_ROUTE: &'static str = "Route";
const C_PATHID: &'static str = "PathId";
const C_ORIGIN: &'static str = "Origin";
const C_NHOP: &'static str = "Nexthop";
const C_ASPATH: &'static str = "Aspath";
const C_COMMS: &'static str = "Comms";
const C_LCOMMS: &'static str = "LargeComms";
const C_ECOMMS: &'static str = "ExtComms";
const C_MED: &'static str = "Med";
const C_LP: &'static str = "Localpref";
const C_ATAGG: &'static str = "AtomicAgg";
const C_AGGAS: &'static str = "AggAs";
const C_ORIG: &'static str = "Originator";
const C_CL: &'static str = "ClusterList";
const C_PMSI: &'static str = "Pmsi_ta";

fn append_columns_for_attribs(v: &mut Vec<Cow<'static, str>>) {
    v.extend_from_slice(&[
        C_ORIGIN.into(),
        C_NHOP.into(),
        C_ASPATH.into(),
        C_COMMS.into(),
        C_LCOMMS.into(),
        C_ECOMMS.into(),
        C_MED.into(),
        C_LP.into(),
        C_ATAGG.into(),
        C_AGGAS.into(),
        C_ORIG.into(),
        C_CL.into(),
        C_PMSI.into(),
    ]);
}
fn append_attribs(
    v: &mut Vec<(Cow<'static, str>, Value)>,
    a: &BgpAttrs,
    type_hints: &IndexMap<String, Type>,
) {
    v.push((
        C_ORIGIN.into(),
        match a.origin {
            zettabgp::message::attributes::origin::BgpAttrOrigin::Egp => {
                klickhouse::Value::string("e")
            }
            zettabgp::message::attributes::origin::BgpAttrOrigin::Igp => {
                klickhouse::Value::string("i")
            }
            _ => klickhouse::Value::string("?"),
        },
    ));
    v.push((
        C_NHOP.into(),
        klickhouse::Value::string(a.nexthop.to_string()),
    ));
    v.push((
        C_ASPATH.into(),
        klickhouse::Value::string(a.aspath.to_string()),
    ));
    v.push((
        C_COMMS.into(),
        klickhouse::Value::Array(
            a.comms
                .value
                .iter()
                .map(|c| klickhouse::Value::string(c.to_string()))
                .collect(),
        ),
    ));
    v.push((
        C_LCOMMS.into(),
        klickhouse::Value::Array(
            a.lcomms
                .value
                .iter()
                .map(|c| klickhouse::Value::string(c.to_string()))
                .collect(),
        ),
    ));
    v.push((
        C_ECOMMS.into(),
        klickhouse::Value::Array(
            a.extcomms
                .value
                .iter()
                .map(|c| klickhouse::Value::string(c.to_string()))
                .collect(),
        ),
    ));
    if let Some(m) = a.med.as_ref() {
        v.push((C_MED.into(), klickhouse::Value::UInt32(*m)));
    } else {
        v.push((C_MED.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.localpref.as_ref() {
        v.push((C_LP.into(), klickhouse::Value::UInt32(*m)));
    } else {
        v.push((C_LP.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.atomicaggregate.as_ref() {
        v.push((C_ATAGG.into(), klickhouse::Value::string(m.to_string())));
    } else {
        v.push((C_ATAGG.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.aggregatoras.as_ref() {
        v.push((C_AGGAS.into(), klickhouse::Value::string(m.to_string())));
    } else {
        v.push((C_AGGAS.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.originator.as_ref() {
        v.push((C_ORIG.into(), klickhouse::Value::string(m.to_string())));
    } else {
        v.push((C_ORIG.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.clusterlist.as_ref() {
        v.push((
            C_CL.into(),
            klickhouse::Value::Array(
                m.value
                    .iter()
                    .map(|c| klickhouse::Value::string(c.to_string()))
                    .collect(),
            ),
        ));
    } else {
        v.push((C_CL.into(), klickhouse::Value::Array(vec![])));
    }
    if type_hints.contains_key(C_PMSI) {
        if let Some(m) = a.pmsi_ta.as_ref() {
            v.push((C_PMSI.into(), klickhouse::Value::string(m.to_string())));
        } else {
            v.push((C_PMSI.into(), klickhouse::Value::Null));
        }
    }
}
struct RibRowU {
    t: Timestamp,
    s: BgpSessionId,
    rd: Option<u64>,
    labels: Option<MplsLabels>,
    route: String,
    pathid: u32,
    a: Arc<BgpAttrs>,
}
impl RibRowU {
    fn new<T: BgpRIBKey + Display>(
        t: Timestamp,
        s: BgpSessionId,
        k: T,
        pathid: u32,
        a: Arc<BgpAttrs>,
    ) -> Self {
        Self {
            t,
            s,
            rd: k.getrd().map(|r| r.to_u64()),
            labels: k.getlabels(),
            route: k.inner_string(),
            pathid,
            a,
        }
    }
}
impl klickhouse::Row for RibRowU {
    const COLUMN_COUNT: Option<usize> = None; //Some(18);
    fn column_names() -> Option<Vec<Cow<'static, str>>> {
        let mut v = vec![
            C_WHEN.into(),
            C_SESSION.into(),
            C_ACTIVE.into(),
            C_ROUTE.into(),
            C_PATHID.into(),
        ];
        append_columns_for_attribs(&mut v);
        Some(v)
    }
    fn deserialize_row(_map: Vec<(&str, &Type, Value)>) -> Result<Self> {
        unimplemented!()
    }
    fn serialize_row(
        self,
        type_hints: &IndexMap<String, Type>,
    ) -> Result<Vec<(Cow<'static, str>, Value)>> {
        let mut v = Vec::new();
        //When DateTime('UTC'),
        v.push((
            C_WHEN.into(),
            klickhouse::Value::DateTime(klickhouse::DateTime(
                klickhouse::Tz::UTC,
                self.t.0.timestamp() as u32,
            )),
        ));
        v.push((C_SESSION.into(), klickhouse::Value::UInt32(self.s as u32)));
        if type_hints.contains_key(C_RD) {
            if let Some(r) = self.rd {
                v.push((C_RD.into(), klickhouse::Value::UInt64(r)));
            }
        }
        v.push((C_ROUTE.into(), klickhouse::Value::string(self.route)));
        v.push((C_PATHID.into(), klickhouse::Value::UInt32(self.pathid)));
        v.push((C_ACTIVE.into(), klickhouse::Value::UInt8(1)));
        if type_hints.contains_key(C_LABELS) {
            if let Some(l) = self.labels {
                v.push((
                    C_LABELS.into(),
                    klickhouse::Value::Array(
                        l.labels
                            .iter()
                            .map(|c| klickhouse::Value::UInt32(*c))
                            .collect(),
                    ),
                ));
            }
        }
        append_attribs(&mut v, self.a.as_ref(), type_hints);
        Ok(v)
    }
}
struct RibRowW {
    t: Timestamp,
    s: BgpSessionId,
    rd: Option<u64>,
    route: String,
    pathid: u32,
}
impl RibRowW {
    fn new<T: BgpRIBKey + Display>(t: Timestamp, s: BgpSessionId, k: T, pathid: u32) -> Self {
        Self {
            t,
            s,
            rd: k.getrd().map(|r| r.to_u64()),
            route: k.inner_string(),
            pathid,
        }
    }
}
impl klickhouse::Row for RibRowW {
    const COLUMN_COUNT: Option<usize> = Some(5);
    fn column_names() -> Option<Vec<Cow<'static, str>>> {
        Some(vec![
            C_WHEN.into(),
            C_SESSION.into(),
            C_ACTIVE.into(),
            C_ROUTE.into(),
            C_PATHID.into(),
        ])
    }
    fn deserialize_row(_map: Vec<(&str, &Type, Value)>) -> Result<Self> {
        unimplemented!()
    }
    fn serialize_row(
        self,
        type_hints: &IndexMap<String, Type>,
    ) -> Result<Vec<(Cow<'static, str>, Value)>> {
        let mut v = Vec::new();
        v.push((
            C_WHEN.into(),
            klickhouse::Value::DateTime(klickhouse::DateTime(
                klickhouse::Tz::UTC,
                self.t.0.timestamp() as u32,
            )),
        ));
        v.push((C_SESSION.into(), klickhouse::Value::UInt32(self.s as u32)));
        v.push((C_ACTIVE.into(), klickhouse::Value::UInt8(1)));
        if type_hints.contains_key(C_RD) {
            if let Some(r) = self.rd {
                v.push((C_RD.into(), klickhouse::Value::UInt64(r)));
            }
        }
        v.push((C_ROUTE.into(), klickhouse::Value::string(self.route)));
        v.push((C_PATHID.into(), klickhouse::Value::UInt32(self.pathid)));
        Ok(v)
    }
}
/*
fn ipaddr2val(a: IpAddr) -> klickhouse::Value {
    match a {
        IpAddr::V4(a4) => klickhouse::Value::Ipv4(klickhouse::Ipv4(a4)),
        IpAddr::V6(a6) => klickhouse::Value::Ipv6(klickhouse::Ipv6(a6)),
    }
}
*/
pub struct ReceiverStream<T> {
    inner: Arc<parking_lot::Mutex<Receiver<T>>>,
}

impl<T> ReceiverStream<T> {
    pub fn new(recv: Arc<parking_lot::Mutex<Receiver<T>>>) -> Self {
        Self { inner: recv }
    }
}

impl<T> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut futures::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.lock().poll_recv(cx)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let inner = self.inner.lock();
        if inner.is_closed() {
            let used_capacity = inner.max_capacity() - inner.capacity();
            (inner.len(), Some(used_capacity))
        } else {
            (inner.len(), None)
        }
    }
}
//<T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static>
struct InserterChannel<T: klickhouse::Row + Send + Sync + 'static> {
    pub(crate) tx: Sender<Vec<T>>,
    pub(crate) task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl<T: klickhouse::Row + Send + Sync + 'static> InserterChannel<T> {
    fn new(
        ribtype: &'static str,
        click: klickhouse::ConnectionManager,
        cso: &ClickhouseStorageOptions,
    ) -> Self {
        let (tx, rx) = channel::<Vec<T>>(100);
        let ribt = ribtype;
        let batch_size = cso.batch_size;
        let batch_dur = cso.batch_dur;
        let break_count = cso.break_count;
        let task = tokio::spawn(async move {
            let client = click.connect().await?;
            let sql = format!("INSERT INTO bgprib_{} FORMAT native", ribt);
            let mrx = Arc::new(parking_lot::Mutex::new(rx));
            loop {
                let rbt = ribtype;
                let strm = ReceiverStream::new(mrx.clone())
                    .chunks_timeout(batch_size, batch_dur)
                    .map(move |v| {
                        //v.into_flattened()
                        let mut r = Vec::new();
                        for mut i in v.into_iter() {
                            r.append(&mut i);
                        }
                        r.shrink_to_fit();
                        r
                    })
                    .take(break_count);
                let strm = Box::pin(strm);
                client.insert_native(&sql, strm).await?;
                debug!("rib {} insert done", rbt);
                if mrx.lock().is_closed() {
                    break;
                }
            }
            Ok(())
        });
        Self { tx, task }
    }
    fn is_finished(&self) -> bool {
        self.tx.is_closed() || self.task.is_finished()
    }
}
impl ClickhouseStorage {
    pub async fn new<A: tokio::net::ToSocketAddrs>(
        target: A,
        client_options: klickhouse::ClientOptions,
        cso: ClickhouseStorageOptions,
    ) -> anyhow::Result<ClickhouseStorage> {
        /*
        let targets: Vec<_> = tokio::net::lookup_host(target).await?.collect();
        let client = tokio::sync::RwLock::new(
            klickhouse::Client::connect::<&[std::net::SocketAddr]>(
                targets.as_ref(),
                client_options.clone(),
            )
            .await?,
        );
        */
        let click = ConnectionManager::new(target, client_options)
            .await
            .with_context(|| format!("create ConnectionManager"))?;
        Ok(ClickhouseStorage {
            click,
            sessions: tokio::sync::RwLock::new(BTreeMap::new()),
            sids: std::sync::RwLock::new(BTreeMap::new()),
            cso,
            upd: tokio::sync::RwLock::new(BTreeMap::new()),
            wdr: tokio::sync::RwLock::new(BTreeMap::new()),
        })
    }
    async fn check_connected(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn reg_session(&self, sess: Arc<BgpSessionDesc>, offer: BgpSessionId) -> BgpSessionId {
        let a1 = sess.peer1.addr;
        let a2 = sess.peer2.addr;
        let k = if a1 < a2 { (a1, a2) } else { (a2, a1) };
        if let Some(bid) = self.sessions.read().await.get(&k).cloned() {
            return bid;
        }
        let mut wg = self.sessions.write().await;
        if let Some(bid) = wg.get(&k).cloned() {
            return bid;
        }
        let client = match self.click.connect().await {
            Ok(c) => c,
            Err(e) => {
                error!("connect error: {:?}", e);
                if offer != 0 {
                    (*wg).insert(k.clone(), offer);
                    self.sids.write().unwrap().insert(offer, k);
                }
                return offer;
            }
        };
        #[derive(Row, Debug, Default)]
        pub struct MyId {
            id: u32,
        }
        if let Ok(r) = client
            .query_one::<MyId>(format!(
                "select id from sessions where instance='{}' and peer1='{}' and peer2='{}'",
                self.cso.instance_id, a1, a2
            ))
            .await
        {
            if r.id > 0 {
                let q = r.id as BgpSessionId;
                (*wg).insert(k.clone(), q);
                self.sids.write().unwrap().insert(q, k);
                return q;
            }
        }
        if let Ok(r) = client
            .query_one::<MyId>("select max(id) as id from sessions")
            .await
        {
            let q = (r.id + 1) as BgpSessionId;
            (*wg).insert(k.clone(), q);
            self.sids.write().unwrap().insert(q, k);

            #[derive(Row)]
            pub struct NewId {
                id: u32,
                instance: String,
                peer1: String,
                peer2: String,
            }
            if let Err(e) = client
                .insert_native_block(
                    "INSERT INTO sessions FORMAT native",
                    vec![NewId {
                        id: q as u32,
                        instance: self.cso.instance_id.clone(),
                        peer1: a1.to_string(),
                        peer2: a2.to_string(),
                    }],
                )
                .await
            {
                error!("insert into sessions error: {:?}", e);
            }
            return q;
        }
        (*wg).insert(k.clone(), offer);
        self.sids.write().unwrap().insert(offer, k);
        offer
    }
    async fn inserter_updates(
        &self,
        ribtype: &'static str,
    ) -> anyhow::Result<Sender<Vec<RibRowU>>> {
        if let Some(i) = self.upd.read().await.get(ribtype) {
            if !i.is_finished() {
                return Ok(i.tx.clone());
            }
        }
        let mut wg = self.upd.write().await;
        let ic = wg.remove(ribtype);
        if let Some(i) = ic {
            if !i.is_finished() {
                let rt = i.tx.clone();
                wg.insert(ribtype, i);
                return Ok(rt);
            }
            if let Ok(je) = i.task.await {
                if let Err(e) = je {
                    error!("InserterChannel update {} error: {:?}", ribtype, e);
                }
            }
        }
        let i = InserterChannel::new(ribtype, self.click.clone(), &self.cso);
        let rt = i.tx.clone();
        wg.insert(ribtype, i);
        Ok(rt)
    }
    async fn inserter_withdraws(
        &self,
        ribtype: &'static str,
    ) -> anyhow::Result<Sender<Vec<RibRowW>>> {
        if let Some(i) = self.wdr.read().await.get(ribtype) {
            if !i.is_finished() {
                return Ok(i.tx.clone());
            }
        }
        let mut wg = self.wdr.write().await;
        let ic = wg.remove(ribtype);
        if let Some(i) = ic {
            if !i.is_finished() {
                let rt = i.tx.clone();
                wg.insert(ribtype, i);
                return Ok(rt);
            }
            if let Ok(je) = i.task.await {
                if let Err(e) = je {
                    error!("InserterChannel withdraw {} error: {:?}", ribtype, e);
                }
            }
        }
        let i = InserterChannel::new(ribtype, self.click.clone(), &self.cso);
        let rt = i.tx.clone();
        wg.insert(ribtype, i);
        Ok(rt)
    }
    async fn out_upd<T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let rows: Vec<_> = v
            .iter()
            .map(|q| RibRowU::new(when, session, q.clone(), 0, rattr.clone()))
            .collect();
        let ins = self
            .inserter_updates(ribtype)
            .await
            .with_context(|| format!("out_upd inserter_updates {}", ribtype))?;
        if let Err(e) = ins.send(rows).await {
            self.check_connected()
                .await
                .with_context(|| format!("out_upd check_connected {}", ribtype))?;
            let ins = self
                .inserter_updates(ribtype)
                .await
                .with_context(|| format!("out_upd inserter_updates double {}", ribtype))?;
            if ins.send(e.0).await.is_err() {
                return Err(anyhow!("Unable to insert rows into {}", ribtype));
            }
        }
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
        let rows: Vec<_> = v
            .iter()
            .map(|q| RibRowU::new(when, session, q.nlri.clone(), q.pathid, rattr.clone()))
            .collect();
        let ins = self
            .inserter_updates(ribtype)
            .await
            .with_context(|| format!("out_upd_path inserter_updates {}", ribtype))?;
        if let Err(e) = ins.send(rows).await {
            self.check_connected()
                .await
                .with_context(|| format!("out_upd_path check_connected {}", ribtype))?;
            let ins = self
                .inserter_updates(ribtype)
                .await
                .with_context(|| format!("out_upd_path inserter_updates double {}", ribtype))?;
            if ins.send(e.0).await.is_err() {
                return Err(anyhow!("Unable to insert rows into {}", ribtype));
            }
        }
        Ok(())
    }
    async fn out_wdr<T: BgpRIBKey + Display + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        v: &[T],
    ) -> anyhow::Result<()> {
        let rows: Vec<_> = v
            .iter()
            .map(|q| RibRowW::new(when, session, q.clone(), 0))
            .collect();
        let ins: Sender<Vec<RibRowW>> = self
            .inserter_withdraws(ribtype)
            .await
            .with_context(|| format!("out_wdr inserter_withdraws {}", ribtype))?;
        if let Err(e) = ins.send(rows).await {
            self.check_connected()
                .await
                .with_context(|| format!("out_wdr check_connected {}", ribtype))?;
            let ins = self
                .inserter_withdraws(ribtype)
                .await
                .with_context(|| format!("out_wdr inserter_withdraws double {}", ribtype))?;
            if ins.send(e.0).await.is_err() {
                return Err(anyhow!("Unable to insert rows into {}", ribtype));
            }
        }
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
        let rows: Vec<_> = v
            .iter()
            .map(|q| RibRowW::new(when, session, q.nlri.clone(), q.pathid))
            .collect();
        let ins: Sender<Vec<RibRowW>> = self
            .inserter_withdraws(ribtype)
            .await
            .with_context(|| format!("out_wdr_path inserter_withdraws {}", ribtype))?;
        if let Err(e) = ins.send(rows).await {
            self.check_connected()
                .await
                .with_context(|| format!("out_wdr_path check_connected {}", ribtype))?;
            let ins = self
                .inserter_withdraws(ribtype)
                .await
                .with_context(|| format!("out_wdr_path inserter_withdraws double {}", ribtype))?;
            if ins.send(e.0).await.is_err() {
                return Err(anyhow!("Unable to insert rows into {}", ribtype));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for ClickhouseStorage {
    async fn open(&mut self) -> anyhow::Result<()> {
        let client = self.click.connect().await?;
        if let Err(e) = client
            .execute_now(
                "CREATE TABLE IF NOT EXISTS sessions (
    `id` UInt32,
    `instance` String,
    `peer1` String,
    `peer2` String
) ENGINE = MergeTree PRIMARY KEY id ORDER BY id",
            )
            .await
        {
            warn!("Clickhouse open error: {:?}", e);
        }
        let mut buf = bytes::BytesMut::new();
        for (rib, flg) in RIB_FLAGS {
            buf.clear();
            write!(
                &mut buf,
                "CREATE TABLE if not exists bgprib_{} (When DateTime('UTC'),SessionId UInt32,",
                rib
            )?;
            if flg & 2 > 0 {
                write!(&mut buf, "RD UInt64,")?;
            }
            write!(&mut buf, "Route String,PathId UInt32,")?;
            if flg & 1 > 0 {
                write!(&mut buf, "Labels Array(UInt32),")?;
            }
            write!(&mut buf,"Active UInt8,Origin Nullable(String),Nexthop Nullable(String),Aspath Nullable(String),
Comms Array(String),LargeComms Array(String),ExtComms Array(String),Med Nullable(UInt32),Localpref Nullable(UInt32),AtomicAgg Nullable(String),
AggAs Nullable(String),Originator Nullable(String),ClusterList Array(String)")?;
            if flg & 4 > 0 {
                write!(&mut buf, ",Pmsi_ta  Nullable(String)")?;
            }
            write!(
                &mut buf,
                ")ENGINE = MergeTree() primary key (When,SessionId,"
            )?;
            if flg & 2 > 0 {
                write!(&mut buf, "RD,")?;
            }
            write!(&mut buf, "Route,PathId) ORDER BY (When,SessionId,")?;

            if flg & 2 > 0 {
                write!(&mut buf, "RD,")?;
            }
            write!(&mut buf, "Route,PathId)")?;
            if !self.cso.partition_by.is_empty() {
                write!(&mut buf, "PARTITION BY {}", self.cso.partition_by)?;
            }
            write!(&mut buf, " TTL {}", self.cso.table_ttl)?;

            if let Err(e) = client
                .execute_now(String::from_utf8_lossy(&buf).to_string())
                .await
            {
                warn!("Clickhouse open error: {:?}", e);
            }
        }
        Ok(())
    }
    async fn shutdown(&self) -> anyhow::Result<()> {
        //self.client.close
        Ok(())
    }
    async fn register_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId> {
        Ok(self.reg_session(sess, offer).await)
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
