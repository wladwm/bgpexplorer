use super::Storage;
use crate::bgpattrs::BgpAttrs;
use crate::bgprib::BgpRIBKey;
use crate::bgpsvc::{BgpSessionDesc, BgpSessionId};
use crate::timestamp::Timestamp;
use crate::BgpRibKind;
use anyhow::Context;
use async_trait::async_trait;
use futures::task::Poll;
use futures::FutureExt;
use futures_util::stream::Stream;
use klickhouse::bb8::ManageConnection;
use klickhouse::*;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_stream::StreamExt;
use zettabgp::afi::{BgpAddrV4, BgpAddrV6, MplsLabels};
use zettabgp::prelude::{BgpAddrs, BgpRD, WithPathId};

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
    sids: parking_lot::RwLock<BTreeMap<BgpSessionId, (IpAddr, IpAddr)>>,
    click: klickhouse::ConnectionManager,
    upd: tokio::sync::RwLock<BTreeMap<&'static str, InserterChannel<RibRowU>>>,
    wdr: tokio::sync::RwLock<BTreeMap<&'static str, InserterChannel<RibRowW>>>,
}

struct RibFields {
    flags: u8, //flag: 0-RD;1-Labels;2-PMSI
    route: &'static str,
    nexthop: &'static str,
}
const ROUTE_STR_TYPE: &'static str = "String";
const ROUTE_IPV4_TYPE: &'static str = "Tuple(IPv4,UInt8)";
const ROUTE_IPV6_TYPE: &'static str = "Tuple(IPv6,UInt8)";
const NH_IPV4_TYPE: &'static str = "Nullable(IPv4)";
const NH_IPV6_TYPE: &'static str = "Nullable(IPv6)";
//flag: 0-RD;1-Labels;2-PMSI
const RIB_FLAGS: [(&'static str, RibFields); 18] = [
    (
        BgpRibKind::RIB_IPV4U,
        RibFields {
            flags: 0,
            route: ROUTE_IPV4_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV4M,
        RibFields {
            flags: 0,
            route: ROUTE_IPV4_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV4LU,
        RibFields {
            flags: 1,
            route: ROUTE_IPV4_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_VPNV4U,
        RibFields {
            flags: 3,
            route: ROUTE_IPV4_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_VPNV4M,
        RibFields {
            flags: 3,
            route: ROUTE_IPV4_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV6U,
        RibFields {
            flags: 0,
            route: ROUTE_IPV6_TYPE,
            nexthop: NH_IPV6_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV6LU,
        RibFields {
            flags: 1,
            route: ROUTE_IPV6_TYPE,
            nexthop: NH_IPV6_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_VPNV6U,
        RibFields {
            flags: 3,
            route: ROUTE_IPV6_TYPE,
            nexthop: NH_IPV6_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_VPNV6M,
        RibFields {
            flags: 3,
            route: ROUTE_IPV6_TYPE,
            nexthop: NH_IPV6_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_L2VPLS,
        RibFields {
            flags: 3,
            route: "Tuple(UInt16,UInt16,UInt16)",
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_MVPN,
        RibFields {
            flags: 7,
            route: "Tuple(UInt8,UInt64,IPv4,UInt8,UInt32,IPv4,UInt8,IPv4,IPv4)",
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_EVPN,
        RibFields {
            flags: 3,
            route: "Tuple(UInt8,UInt64,UInt8,String,UInt32,Array(UInt32),String,IPv4,UInt8,IPv4)",
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_FS4U,
        RibFields {
            flags: 0,
            route: ROUTE_STR_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_FS6U,
        RibFields {
            flags: 0,
            route: ROUTE_STR_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_FSV4U,
        RibFields {
            flags: 2,
            route: ROUTE_STR_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_FSV6U,
        RibFields {
            flags: 2,
            route: ROUTE_STR_TYPE,
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV4MDT,
        RibFields {
            flags: 0,
            route: "Tuple(IPv4,UInt8,IPv4)",
            nexthop: NH_IPV4_TYPE,
        },
    ),
    (
        BgpRibKind::RIB_IPV6MDT,
        RibFields {
            flags: 0,
            route: "Tuple(IPv6,UInt8,IPv6)",
            nexthop: NH_IPV6_TYPE,
        },
    ),
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
Route Tuple(IPv4,UInt8),
PathId UInt32,
Active UInt8,
Origin FixedString(1),
Nexthop Nullable(IPv4),
Aspath Nullable(String),
Comms Array(String),
LargeComms Array(String),
ExtComms Array(String),
Med Nullable(UInt32),
Localpref Nullable(UInt32),
AtomicAgg Nullable(IPv4),
AggAs Tuple(UInt32,IPv4),
Originator  Nullable(IPv4),
ClusterList  Array(IPv4)
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

rename table bgprib_evpn    to old_evpn;
rename table bgprib_fs4u    to old_fs4u;
rename table bgprib_fs6u    to old_fs6u;
rename table bgprib_fsv4u   to old_fsv4u;
rename table bgprib_fsv6u   to old_fsv6u;
rename table bgprib_ipv4lu  to old_ipv4lu;
rename table bgprib_ipv4m   to old_ipv4m;
rename table bgprib_ipv4mdt to old_ipv4mdt;
rename table bgprib_ipv4u   to old_ipv4u;
rename table bgprib_ipv6lu  to old_ipv6lu;
rename table bgprib_ipv6mdt to old_ipv6mdt;
rename table bgprib_ipv6u   to old_ipv6u;
rename table bgprib_l2vpls  to old_l2vpls;
rename table bgprib_mvpn    to old_mvpn;
rename table bgprib_vpnv4m  to old_vpnv4m;
rename table bgprib_vpnv4u  to old_vpnv4u;
rename table bgprib_vpnv6m  to old_vpnv6m;
rename table bgprib_vpnv6u  to old_vpnv6u;

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
        match &a.nexthop {
            zettabgp::afi::BgpAddr::V4(v4) => klickhouse::Value::Ipv4(v4.clone().into()),
            zettabgp::afi::BgpAddr::V4RD(v4) => klickhouse::Value::Ipv4(v4.addr.into()),
            zettabgp::afi::BgpAddr::V6(v6) => klickhouse::Value::Ipv6(v6.clone().into()),
            zettabgp::afi::BgpAddr::V6RD(v6) => klickhouse::Value::Ipv6(v6.addr.into()),
            _ => klickhouse::Value::Null,
        },
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
        v.push((C_ATAGG.into(), klickhouse::Value::Ipv4(m.clone().into())));
    } else {
        v.push((C_ATAGG.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.aggregatoras.as_ref() {
        v.push((
            C_AGGAS.into(),
            klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt32(m.asn),
                klickhouse::Value::Ipv4(m.addr.into()),
            ]),
        ));
    } else {
        v.push((
            C_AGGAS.into(),
            klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt32(0),
                klickhouse::Value::Ipv4(std::net::Ipv4Addr::new(0, 0, 0, 0).into()),
            ]),
        ));
    }
    if let Some(m) = a.originator.as_ref() {
        match m {
            std::net::IpAddr::V4(x) => {
                v.push((C_ORIG.into(), klickhouse::Value::Ipv4(x.clone().into())))
            }
            _ => v.push((C_ORIG.into(), klickhouse::Value::Null)),
        };
    } else {
        v.push((C_ORIG.into(), klickhouse::Value::Null));
    }
    if let Some(m) = a.clusterlist.as_ref() {
        v.push((
            C_CL.into(),
            klickhouse::Value::Array(
                m.value
                    .iter()
                    .map(|c| match c {
                        std::net::IpAddr::V4(v4) => Some(v4.clone()),
                        _ => None,
                    })
                    .filter(|c| c.is_some())
                    .map(|c| c.unwrap())
                    .map(|c| klickhouse::Value::Ipv4(c.into()))
                    .collect(),
            ),
        ));
    } else {
        v.push((C_CL.into(), klickhouse::Value::Array(vec![])));
    }
    if type_hints.contains_key(C_PMSI) {
        if let Some(m) = a.pmsi_ta.as_ref() {
            //v.push((C_PMSI.into(), klickhouse::Value::string(m.to_string())));
            v.push((C_PMSI.into(), pmsi_to_ch_value(m)));
        } else {
            v.push((C_PMSI.into(), PMSI_EMPTY.clone()));
        }
    }
}
lazy_static! {
    static ref IPV4_ZERO: klickhouse::Value =
        klickhouse::Value::Ipv4(std::net::Ipv4Addr::new(0, 0, 0, 0).into());
    static ref STR_EMPTY: klickhouse::Value = klickhouse::Value::string("");
    static ref PMSI_EMPTY: klickhouse::Value = klickhouse::Value::Tuple(vec![
        klickhouse::Value::UInt8(0),
        klickhouse::Value::UInt8(0),
        klickhouse::Value::Array(Vec::new()),
        klickhouse::Value::UInt8(255),
        IPV4_ZERO.clone(),
        klickhouse::Value::UInt16(0),
        klickhouse::Value::UInt16(0),
        IPV4_ZERO.clone()
    ]);
}
fn ipaddr_to_ch(a: &std::net::IpAddr) -> klickhouse::Value {
    match a {
        std::net::IpAddr::V4(v4) => klickhouse::Value::Ipv4(v4.clone().into()),
        _ => IPV4_ZERO.clone(),
    }
}
fn pmsi_to_ch_value(pmsi: &zettabgp::prelude::BgpPMSITunnel) -> klickhouse::Value {
    use zettabgp::prelude::BgpPMSITunnelAttr;
    //Tuple(UInt8,UInt8,Array(UInt32),UInt8,IPv4,UInt16,UInt16,IPv4)
    //klickhouse::Value::string(pmsi.to_string())
    let mut v = vec![
        klickhouse::Value::UInt8(pmsi.tunnel_type),
        klickhouse::Value::UInt8(pmsi.flags),
        klickhouse::Value::Array(
            pmsi.label
                .labels
                .iter()
                .cloned()
                .map(|x| klickhouse::Value::UInt32(x))
                .collect(),
        ),
    ];
    match &pmsi.tunnel_attribute {
        BgpPMSITunnelAttr::None => {
            v.push(klickhouse::Value::UInt8(0));
            v.push(IPV4_ZERO.clone());
            v.push(klickhouse::Value::UInt16(0));
            v.push(klickhouse::Value::UInt16(0));
            v.push(IPV4_ZERO.clone());
        }
        BgpPMSITunnelAttr::RSVPTe(t) => {
            v.push(klickhouse::Value::UInt8(1));
            v.push(klickhouse::Value::Ipv4(t.ext_tunnel_id.clone().into()));
            v.push(klickhouse::Value::UInt16(t.reserved));
            v.push(klickhouse::Value::UInt16(t.tunnel_id));
            v.push(klickhouse::Value::Ipv4(t.p2mp_id.clone().into()));
        }
        BgpPMSITunnelAttr::IngressRepl(r) => {
            v.push(klickhouse::Value::UInt8(2));
            v.push(klickhouse::Value::Ipv4(r.endpoint.clone().into()));
            v.push(klickhouse::Value::UInt16(0));
            v.push(klickhouse::Value::UInt16(0));
            v.push(IPV4_ZERO.clone());
        }
        BgpPMSITunnelAttr::MLDP(l) => {
            v.push(klickhouse::Value::UInt8(3));
            v.push(ipaddr_to_ch(&l.rootnode));
            v.push(klickhouse::Value::UInt16(0));
            v.push(klickhouse::Value::UInt16(0));
            v.push(IPV4_ZERO.clone());
        }
    };
    klickhouse::Value::Tuple(v)
}
trait ToChField: BgpRIBKey + std::fmt::Display {
    fn to_ch_value(&self) -> klickhouse::Value;
}
impl ToChField for BgpAddrV4 {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::Tuple(vec![
            klickhouse::Value::Ipv4(self.addr.clone().into()),
            klickhouse::Value::UInt8(self.prefixlen),
        ])
    }
}
impl ToChField for BgpAddrV6 {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::Tuple(vec![
            klickhouse::Value::Ipv6(self.addr.clone().into()),
            klickhouse::Value::UInt8(self.prefixlen),
        ])
    }
}
impl ToChField for zettabgp::afi::BgpAddrL2 {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::Tuple(vec![
            klickhouse::Value::UInt16(self.site),
            klickhouse::Value::UInt16(self.offset),
            klickhouse::Value::UInt16(self.range),
        ])
    }
}
impl ToChField for zettabgp::afi::BgpMVPN {
    fn to_ch_value(&self) -> klickhouse::Value {
        /*
        Tuple(UInt8,UInt64,IPv4,UInt8,UInt32,IPv4,UInt8,IPv4,IPv4)
        T1(BgpMVPN1),  //Intra AS I-PMSI AD  1:10.255.170.100:1:10.255.170.100
        T2(BgpMVPN2),  //Inter AS I-PMSI AD  2:10.255.170.100:1:65000
        T3(BgpMVPN3), //S-PMSI AD           3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100
        T4(BgpMVPN4), //Leaf AD             4:3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100:10.255.170.98
        T5(BgpMVPN5), //Source Active AD    5:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3
        T6(BgpMVPN67), //Shared Tree Join    6:10.255.170.100:1:65000:32:10.12.53.12:32:224.1.2.3
        T7(BgpMVPN67), //Source Tree Join    7:10.255.170.100:1:65000:32:192.168.194.2:32:224.1.2.3
            */
        match self {
            zettabgp::afi::BgpMVPN::T1(t1) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(1),
                klickhouse::Value::UInt64(t1.rd.to_u64()),
                ipaddr_to_ch(&t1.originator),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(0),
                IPV4_ZERO.clone(),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpMVPN::T2(t2) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(2),
                klickhouse::Value::UInt64(t2.rd.to_u64()),
                IPV4_ZERO.clone(),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(t2.asn),
                IPV4_ZERO.clone(),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpMVPN::T3(t3) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(3),
                klickhouse::Value::UInt64(t3.rd.to_u64()),
                ipaddr_to_ch(&t3.source),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(0),
                ipaddr_to_ch(&t3.group),
                klickhouse::Value::UInt8(0),
                ipaddr_to_ch(&t3.originator),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpMVPN::T4(t4) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(4),
                klickhouse::Value::UInt64(t4.spmsi.rd.to_u64()),
                ipaddr_to_ch(&t4.spmsi.source),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(0),
                ipaddr_to_ch(&t4.spmsi.group),
                klickhouse::Value::UInt8(0),
                ipaddr_to_ch(&t4.spmsi.originator),
                ipaddr_to_ch(&t4.originator),
            ]),
            zettabgp::afi::BgpMVPN::T5(t5) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(5),
                klickhouse::Value::UInt64(t5.rd.to_u64()),
                ipaddr_to_ch(&t5.source),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(0),
                ipaddr_to_ch(&t5.group),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpMVPN::T6(t) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(6),
                klickhouse::Value::UInt64(t.rd.to_u64()),
                ipaddr_to_ch(&t.rp),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(t.asn),
                ipaddr_to_ch(&t.group),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpMVPN::T7(t) => klickhouse::Value::Tuple(vec![
                klickhouse::Value::UInt8(7),
                klickhouse::Value::UInt64(t.rd.to_u64()),
                ipaddr_to_ch(&t.rp),
                klickhouse::Value::UInt8(0),
                klickhouse::Value::UInt32(t.asn),
                ipaddr_to_ch(&t.group),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
                IPV4_ZERO.clone(),
            ]),
            //_ => klickhouse::Value::string(self.to_string())
        }
    }
}
impl ToChField for zettabgp::afi::BgpEVPN {
    fn to_ch_value(&self) -> klickhouse::Value {
        //klickhouse::Value::string(self.to_string())
        //Tuple(UInt8,UInt64,UInt8,String,UInt32,Array(UInt32),String,IPv4,UInt8,IPv4)
        match self {
            zettabgp::afi::BgpEVPN::EVPN1(t1) => klickhouse::Value::Tuple(vec![
                /*
                pub rd: BgpRD,
                pub esi_type: u8,
                pub esi: EVPNESI,
                pub ether_tag: u32,
                pub labels: MplsLabels,
                    */
                klickhouse::Value::UInt8(1),
                klickhouse::Value::UInt64(t1.rd.to_u64()),
                klickhouse::Value::UInt8(t1.esi_type),
                klickhouse::Value::string(format!("{}", t1.esi)),
                klickhouse::Value::UInt32(t1.ether_tag),
                klickhouse::Value::Array(
                    t1.labels
                        .labels
                        .iter()
                        .cloned()
                        .map(|x| klickhouse::Value::UInt32(x))
                        .collect(),
                ),
                STR_EMPTY.clone(),
                IPV4_ZERO.clone(),
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpEVPN::EVPN2(t2) => klickhouse::Value::Tuple(vec![
                /*
                pub rd: BgpRD,
                pub esi_type: u8,
                pub esi: EVPNESI,
                pub ether_tag: u32,
                pub mac: MacAddress,
                pub ip: Option<std::net::IpAddr>,
                pub labels: MplsLabels,
                            */
                klickhouse::Value::UInt8(2),
                klickhouse::Value::UInt64(t2.rd.to_u64()),
                klickhouse::Value::UInt8(t2.esi_type),
                klickhouse::Value::string(format!("{}", t2.esi)),
                klickhouse::Value::UInt32(t2.ether_tag),
                klickhouse::Value::Array(
                    t2.labels
                        .labels
                        .iter()
                        .cloned()
                        .map(|x| klickhouse::Value::UInt32(x))
                        .collect(),
                ),
                klickhouse::Value::string(format!("{}", t2.mac)),
                match t2.ip {
                    Some(std::net::IpAddr::V4(ip4)) => klickhouse::Value::Ipv4(ip4.clone().into()),
                    _ => IPV4_ZERO.clone(),
                },
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpEVPN::EVPN3(t3) => klickhouse::Value::Tuple(vec![
                /*
                pub rd: BgpRD,
                pub ether_tag: u32,
                pub ip: std::net::IpAddr,
                            */
                klickhouse::Value::UInt8(3),
                klickhouse::Value::UInt64(t3.rd.to_u64()),
                klickhouse::Value::UInt8(0),
                STR_EMPTY.clone(),
                klickhouse::Value::UInt32(t3.ether_tag),
                klickhouse::Value::Array(vec![]),
                STR_EMPTY.clone(),
                match t3.ip {
                    std::net::IpAddr::V4(ip4) => klickhouse::Value::Ipv4(ip4.clone().into()),
                    _ => IPV4_ZERO.clone(),
                },
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpEVPN::EVPN4(t4) => klickhouse::Value::Tuple(vec![
                /*
                pub rd: BgpRD,
                pub esi_type: u8,
                pub esi: EVPNESI,
                pub ip: std::net::IpAddr,
                            */
                klickhouse::Value::UInt8(4),
                klickhouse::Value::UInt64(t4.rd.to_u64()),
                klickhouse::Value::UInt8(t4.esi_type),
                klickhouse::Value::string(format!("{}", t4.esi)),
                klickhouse::Value::UInt32(0),
                klickhouse::Value::Array(vec![]),
                STR_EMPTY.clone(),
                match t4.ip {
                    std::net::IpAddr::V4(ip4) => klickhouse::Value::Ipv4(ip4.clone().into()),
                    _ => IPV4_ZERO.clone(),
                },
                klickhouse::Value::UInt8(0),
                IPV4_ZERO.clone(),
            ]),
            zettabgp::afi::BgpEVPN::EVPN5(t5) => klickhouse::Value::Tuple(vec![
                /*
                pub rd: BgpRD,
                pub esi_type: u8,
                pub esi: EVPNESI,
                pub ether_tag: u32,
                pub len: u8,
                pub prefix: IpAddr,
                pub gw_ip: IpAddr,
                pub labels: MplsLabels,
                            */
                klickhouse::Value::UInt8(5),
                klickhouse::Value::UInt64(t5.rd.to_u64()),
                klickhouse::Value::UInt8(t5.esi_type),
                klickhouse::Value::string(format!("{}", t5.esi)),
                klickhouse::Value::UInt32(t5.ether_tag),
                klickhouse::Value::Array(
                    t5.labels
                        .labels
                        .iter()
                        .cloned()
                        .map(|x| klickhouse::Value::UInt32(x))
                        .collect(),
                ),
                STR_EMPTY.clone(),
                match t5.prefix {
                    std::net::IpAddr::V4(ip4) => klickhouse::Value::Ipv4(ip4.clone().into()),
                    _ => IPV4_ZERO.clone(),
                },
                klickhouse::Value::UInt8(t5.len),
                match t5.gw_ip {
                    std::net::IpAddr::V4(ip4) => klickhouse::Value::Ipv4(ip4.clone().into()),
                    _ => IPV4_ZERO.clone(),
                },
            ]),
        }
    }
}
impl ToChField for zettabgp::afi::BgpMdtV4 {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::Tuple(vec![
            klickhouse::Value::Ipv4(self.addr.addr.clone().into()),
            klickhouse::Value::UInt8(self.addr.prefixlen),
            klickhouse::Value::Ipv4(self.group.clone().into()),
        ])
    }
}
impl ToChField for zettabgp::afi::BgpMdtV6 {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::Tuple(vec![
            klickhouse::Value::Ipv6(self.addr.addr.clone().into()),
            klickhouse::Value::UInt8(self.addr.prefixlen),
            klickhouse::Value::Ipv6(self.group.clone().into()),
        ])
    }
}
impl ToChField for zettabgp::afi::BgpFlowSpec<BgpAddrV4> {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::string(self.to_string())
    }
}
impl ToChField for zettabgp::afi::BgpFlowSpec<zettabgp::afi::FS6> {
    fn to_ch_value(&self) -> klickhouse::Value {
        klickhouse::Value::string(self.to_string())
    }
}
impl<T: ToChField + zettabgp::afi::BgpItem<T>> ToChField for zettabgp::afi::Labeled<T> {
    fn to_ch_value(&self) -> klickhouse::Value {
        self.prefix.to_ch_value()
    }
}
impl<T: ToChField + zettabgp::afi::BgpItem<T>> ToChField for zettabgp::afi::WithRd<T> {
    fn to_ch_value(&self) -> klickhouse::Value {
        self.prefix.to_ch_value()
    }
}
struct RibRowU {
    t: Timestamp,
    s: BgpSessionId,
    rd: Option<u64>,
    labels: Option<MplsLabels>,
    route: klickhouse::Value,
    pathid: u32,
    a: Arc<BgpAttrs>,
}
impl RibRowU {
    fn new<T: ToChField>(
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
            route: k.to_ch_value(),
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
        v.push((C_ROUTE.into(), self.route));
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
    route: klickhouse::Value,
    pathid: u32,
}
impl RibRowW {
    fn new<T: ToChField>(t: Timestamp, s: BgpSessionId, k: T, pathid: u32) -> Self {
        Self {
            t,
            s,
            rd: k.getrd().map(|r| r.to_u64()),
            route: k.to_ch_value(),
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
        v.push((C_ACTIVE.into(), klickhouse::Value::UInt8(0)));
        if type_hints.contains_key(C_RD) {
            if let Some(r) = self.rd {
                v.push((C_RD.into(), klickhouse::Value::UInt64(r)));
            }
        }
        v.push((C_ROUTE.into(), self.route));
        v.push((C_PATHID.into(), klickhouse::Value::UInt32(self.pathid)));
        Ok(v)
    }
}
pub struct ReceiverStream<T: Send + 'static> {
    recv: Arc<tokio::sync::Mutex<Receiver<T>>>,
    f: Option<Pin<Box<dyn futures::Future<Output = Option<T>> + Send + Sync>>>,
    finish: tokio::time::Instant,
}

impl<T: Send + 'static> ReceiverStream<T> {
    pub fn new(recv: Arc<tokio::sync::Mutex<Receiver<T>>>, finish: tokio::time::Instant) -> Self {
        Self {
            recv,
            f: None,
            finish,
        }
    }
}

impl<T: Send + 'static> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut futures::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.finish < tokio::time::Instant::now() {
            return Poll::Ready(None);
        }
        let mut f = match self.f.take() {
            None => {
                let rx = self.recv.clone();
                let deadline = self.finish;
                let to = async move {
                    tokio::time::timeout_at(deadline, async move { rx.lock().await.recv().await })
                        .await
                        .ok()
                        .flatten()
                };
                Box::pin(to)
            }
            Some(f) => f,
        };
        let r = f.poll_unpin(cx);
        match r {
            Poll::Ready(q) => {
                return Poll::Ready(q);
            }
            _ => {}
        };
        self.f = Some(f);
        return Poll::Pending;
    }
    /*
    fn size_hint(&self) -> (usize, Option<usize>) {
        let inner = self.recv.lock();
        if inner.is_closed() {
            let used_capacity = inner.max_capacity() - inner.capacity();
            (inner.len(), Some(used_capacity))
        } else {
            (inner.len(), None)
        }
    }
        */
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
            let mrx = Arc::new(tokio::sync::Mutex::new(rx));
            loop {
                let rbt = ribtype;
                let strm = ReceiverStream::new(
                    mrx.clone(),
                    tokio::time::Instant::now() + (batch_dur * (break_count as u32)),
                )
                .chunks_timeout(batch_size, batch_dur)
                .map(move |v| {
                    //v.into_flattened()
                    let mut r = Vec::new();
                    for mut i in v.into_iter() {
                        r.append(&mut i);
                    }
                    r.shrink_to_fit();
                    debug!(
                        "clickhouse InserterChannel {} got {} items",
                        ribtype,
                        r.len()
                    );
                    r
                })
                .take(break_count);
                let strm = Box::pin(strm);
                client.insert_native(&sql, strm).await?;
                debug!("rib {} insert done", rbt);
                if mrx.lock().await.is_closed() {
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
            sids: parking_lot::RwLock::new(BTreeMap::new()),
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
                    self.sids.write().insert(offer, k);
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
                self.sids.write().insert(q, k);
                return q;
            }
        }
        if let Ok(r) = client
            .query_one::<MyId>("select max(id) as id from sessions")
            .await
        {
            let mut q = (r.id + 1) as BgpSessionId;
            while self.sids.read().get(&q).is_some() {
                q += 1;
            }
            (*wg).insert(k.clone(), q);
            self.sids.write().insert(q, k);

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
        self.sids.write().insert(offer, k);
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
    async fn out_upd<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
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
    async fn out_upd_rd<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        rd: BgpRD,
        v: &[T],
    ) -> anyhow::Result<()> {
        let rdu = rd.to_u64();
        let rows: Vec<_> = v
            .iter()
            .map(|q| {
                let mut r = RibRowU::new(when, session, q.clone(), 0, rattr.clone());
                r.rd = Some(rdu);
                r
            })
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
    async fn out_upd_path<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
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
    async fn out_wdr<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
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
    async fn out_wdr_rd<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
        &self,
        ribtype: &'static str,
        session: BgpSessionId,
        when: Timestamp,
        rd: BgpRD,
        v: &[T],
    ) -> anyhow::Result<()> {
        let rdu = rd.to_u64();
        let rows: Vec<_> = v
            .iter()
            .map(|q| {
                let mut r = RibRowW::new(when, session, q.clone(), 0);
                r.rd = Some(rdu);
                r
            })
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
    async fn out_wdr_path<T: ToChField + std::marker::Send + std::marker::Sync + 'static>(
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
        for (rib, fld) in RIB_FLAGS {
            buf.clear();
            write!(
                &mut buf,
                "CREATE TABLE if not exists bgprib_{} (When DateTime('UTC'),SessionId UInt32,",
                rib
            )?;
            if fld.flags & 2 > 0 {
                write!(&mut buf, "RD UInt64,")?;
            }
            write!(&mut buf, "Route {},", fld.route)?;
            write!(&mut buf, "PathId UInt32,")?;
            if fld.flags & 1 > 0 {
                write!(&mut buf, "Labels Array(UInt32),")?;
            }
            write!(&mut buf, "Active UInt8,Origin FixedString(1),")?;
            write!(&mut buf, "Nexthop {},", fld.nexthop)?;
            write!(&mut buf,"Aspath Nullable(String),
Comms Array(String),LargeComms Array(String),ExtComms Array(String),Med Nullable(UInt32),Localpref Nullable(UInt32),AtomicAgg Nullable(IPv4),
AggAs Tuple(UInt32,IPv4),Originator Nullable(IPv4),ClusterList Array(IPv4)")?;
            if fld.flags & 4 > 0 {
                write!(
                    &mut buf,
                    ",Pmsi_ta  Tuple(UInt8,UInt8,Array(UInt32),UInt8,IPv4,UInt16,UInt16,IPv4)"
                )?;
            }
            write!(
                &mut buf,
                ")ENGINE = MergeTree() primary key (When,SessionId,"
            )?;
            if fld.flags & 2 > 0 {
                write!(&mut buf, "RD,")?;
            }
            write!(&mut buf, "Route,PathId) ORDER BY (When,SessionId,")?;

            if fld.flags & 2 > 0 {
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
            BgpAddrs::FSV4U(v) => {
                self.out_upd_rd(
                    BgpRibKind::RIB_FSV4U,
                    session,
                    rattr,
                    when,
                    v.0.clone(),
                    &v.1,
                )
                .await
            }
            BgpAddrs::FS6U(v) => {
                self.out_upd(BgpRibKind::RIB_FS6U, session, rattr, when, v)
                    .await
            }
            BgpAddrs::FSV6U(v) => {
                self.out_upd_rd(
                    BgpRibKind::RIB_FSV6U,
                    session,
                    rattr,
                    when,
                    v.0.clone(),
                    &v.1,
                )
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
            BgpAddrs::FSV4U(v) => {
                self.out_wdr_rd(BgpRibKind::RIB_FS4U, session, when, v.0.clone(), &v.1)
                    .await
            }
            BgpAddrs::FS6U(v) => self.out_wdr(BgpRibKind::RIB_FS6U, session, when, v).await,
            BgpAddrs::FSV6U(v) => {
                self.out_wdr_rd(BgpRibKind::RIB_FS4U, session, when, v.0.clone(), &v.1)
                    .await
            }
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
