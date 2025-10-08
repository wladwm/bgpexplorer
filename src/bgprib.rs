use crate::bgpattrs::*;
use crate::bgpsvc::BgpSessionId;
use crate::config::*;
use crate::ribfilter::RouteFilter;
use crate::ribservice::RibResponseFilter;
use crate::timestamp::Timestamp;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufReader, BufWriter};
use std::iter::Iterator;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::broadcast;
use zettabgp::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpRibKind {
    IpV4u,
    IpV4m,
    IpV4LU,
    VpnV4u,
    VpnV4m,
    IpV6u,
    IpV6LU,
    VpnV6u,
    VpnV6m,
    L2vpls,
    MVpn,
    EVpn,
    Fs4u,
    IpV4mdt,
    Ipv6mdt,
}
impl BgpRibKind {
    pub fn from_bgp_addrs(addrs: &BgpAddrs) -> Option<BgpRibKind> {
        match addrs {
            BgpAddrs::None => None,
            BgpAddrs::IPV4U(_) => Some(BgpRibKind::IpV4u),
            BgpAddrs::IPV4UP(_) => Some(BgpRibKind::IpV4u),
            BgpAddrs::IPV4M(_) => Some(BgpRibKind::IpV4m),
            BgpAddrs::IPV4MP(_) => Some(BgpRibKind::IpV4m),
            BgpAddrs::IPV4LU(_) => Some(BgpRibKind::IpV4LU),
            BgpAddrs::IPV4LUP(_) => Some(BgpRibKind::IpV4LU),
            BgpAddrs::VPNV4U(_) => Some(BgpRibKind::VpnV4u),
            BgpAddrs::VPNV4UP(_) => Some(BgpRibKind::VpnV4u),
            BgpAddrs::VPNV4M(_) => Some(BgpRibKind::VpnV4m),
            BgpAddrs::VPNV4MP(_) => Some(BgpRibKind::VpnV4m),
            BgpAddrs::IPV4MDT(_) => Some(BgpRibKind::IpV4mdt),
            BgpAddrs::IPV4MDTP(_) => Some(BgpRibKind::IpV4mdt),
            BgpAddrs::IPV6U(_) => Some(BgpRibKind::IpV6u),
            BgpAddrs::IPV6UP(_) => Some(BgpRibKind::IpV6u),
            BgpAddrs::IPV6M(_) => None,
            BgpAddrs::IPV6MP(_) => None,
            BgpAddrs::IPV6LU(_) => Some(BgpRibKind::IpV6LU),
            BgpAddrs::IPV6LUP(_) => Some(BgpRibKind::IpV6LU),
            BgpAddrs::VPNV6U(_) => Some(BgpRibKind::VpnV6u),
            BgpAddrs::VPNV6UP(_) => Some(BgpRibKind::VpnV6u),
            BgpAddrs::VPNV6M(_) => Some(BgpRibKind::VpnV6m),
            BgpAddrs::VPNV6MP(_) => Some(BgpRibKind::VpnV6m),
            BgpAddrs::IPV6MDT(_) => Some(BgpRibKind::Ipv6mdt),
            BgpAddrs::IPV6MDTP(_) => Some(BgpRibKind::Ipv6mdt),
            BgpAddrs::L2VPLS(_) => Some(BgpRibKind::Ipv6mdt),
            BgpAddrs::MVPN(_) => Some(BgpRibKind::MVpn),
            BgpAddrs::EVPN(_) => Some(BgpRibKind::EVpn),
            BgpAddrs::FS4U(_) => Some(BgpRibKind::Fs4u),
            BgpAddrs::FS6U(_) => None,
            BgpAddrs::FSV4U(_) => None,
        }
    }
}
impl Default for BgpRibKind {
    fn default() -> BgpRibKind {
        BgpRibKind::IpV4u
    }
}
impl std::str::FromStr for BgpRibKind {
    type Err = BgpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipv4u" => Ok(BgpRibKind::IpV4u),
            "ipv4m" => Ok(BgpRibKind::IpV4m),
            "ipv4lu" => Ok(BgpRibKind::IpV4LU),
            "vpnv4u" => Ok(BgpRibKind::VpnV4u),
            "vpnv4m" => Ok(BgpRibKind::VpnV4m),
            "ipv6u" => Ok(BgpRibKind::IpV6u),
            "ipv6lu" => Ok(BgpRibKind::IpV6LU),
            "vpnv6u" => Ok(BgpRibKind::VpnV6u),
            "vpnv6m" => Ok(BgpRibKind::VpnV6m),
            "l2vpls" => Ok(BgpRibKind::L2vpls),
            "mvpn" => Ok(BgpRibKind::MVpn),
            "evpn" => Ok(BgpRibKind::EVpn),
            "fs4u" => Ok(BgpRibKind::Fs4u),
            "ipv4mdt" => Ok(BgpRibKind::IpV4mdt),
            "ipv6mdt" => Ok(BgpRibKind::Ipv6mdt),
            _ => Err(BgpError::static_str("Invalid RIB kind")),
        }
    }
}
impl std::fmt::Display for BgpRibKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpRibKind::IpV4u => f.write_str("ipv4u"),
            BgpRibKind::IpV4m => f.write_str("ipv4m"),
            BgpRibKind::IpV4LU => f.write_str("ipv4lu"),
            BgpRibKind::VpnV4u => f.write_str("vpnv4u"),
            BgpRibKind::VpnV4m => f.write_str("vpnv4m"),
            BgpRibKind::IpV6u => f.write_str("ipv6u"),
            BgpRibKind::IpV6LU => f.write_str("ipv6lu"),
            BgpRibKind::VpnV6u => f.write_str("vpnv6u"),
            BgpRibKind::VpnV6m => f.write_str("vpnv6m"),
            BgpRibKind::L2vpls => f.write_str("l2vpls"),
            BgpRibKind::MVpn => f.write_str("mvpn"),
            BgpRibKind::EVpn => f.write_str("evpn"),
            BgpRibKind::Fs4u => f.write_str("fs4u"),
            BgpRibKind::IpV4mdt => f.write_str("ipv4mdt"),
            BgpRibKind::Ipv6mdt => f.write_str("ipv6mdt"),
        }
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RibItem<T: std::hash::Hash + Eq + Ord> {
    pub item: Arc<T>,
}
impl<T: std::hash::Hash + Eq + Ord> RibItem<T> {
    pub fn fromrc(itm: &Arc<T>) -> RibItem<T> {
        RibItem { item: itm.clone() }
    }
    pub fn is_empty(&self) -> bool {
        Arc::strong_count(&self.item) < 2
    }
}
impl<T: std::hash::Hash + Eq + Ord + serde::Serialize> serde::Serialize for RibItem<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.item.serialize(serializer)
    }
}
pub struct RibItemStore<T: std::hash::Hash + Eq + Ord> {
    pub items: HashSet<RibItem<T>>,
}
impl<T: std::hash::Hash + Eq + PartialOrd + Ord> Default for RibItemStore<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: std::hash::Hash + Eq + PartialOrd + Ord> RibItemStore<T> {
    pub fn new() -> RibItemStore<T> {
        RibItemStore {
            items: HashSet::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn clear(&mut self) {
        self.items.clear();
    }
    pub fn purge(&mut self) {
        let mut trg = HashSet::<RibItem<T>>::new();
        let mut removed: usize = 0;
        for i in self.items.iter() {
            if !i.is_empty() {
                trg.insert(RibItem::fromrc(&i.item));
            } else {
                removed += 1;
            }
        }
        if removed > 0 {
            self.items = trg;
        }
    }
    pub fn get(&mut self, item: Arc<T>) -> Result<Arc<T>, Box<dyn std::error::Error>> {
        match self.items.get(&RibItem::fromrc(&item)) {
            Some(n) => Ok(n.item.clone()),
            None => {
                self.items.insert(RibItem::fromrc(&item));
                match self.items.get(&RibItem::fromrc(&item)) {
                    Some(n) => Ok(n.item.clone()),
                    None => Err(Box::new(BgpError::from_string(format!(
                        "Unable to register {}",
                        std::any::type_name::<T>()
                    )))),
                }
            }
        }
    }
}
pub trait BgpRIBKey: std::hash::Hash + std::cmp::Eq + std::cmp::Ord + Clone {
    fn getlabels(&self) -> Option<MplsLabels> {
        None
    }
}
impl<T: BgpItem<T> + std::hash::Hash + std::cmp::Eq + std::cmp::Ord + Clone> BgpRIBKey
    for Labeled<T>
{
    fn getlabels(&self) -> Option<MplsLabels> {
        Some(self.labels.clone())
    }
}
impl<T: BgpItem<T> + std::hash::Hash + std::cmp::Eq + std::cmp::Ord + Clone> BgpRIBKey
    for WithRd<T>
{
}

impl BgpRIBKey for BgpAddrL2 {
    fn getlabels(&self) -> Option<MplsLabels> {
        Some(self.labels.clone())
    }
}
impl BgpRIBKey for BgpAddrV4 {}
impl BgpRIBKey for BgpAddrV6 {}
impl BgpRIBKey for BgpMVPN {}
impl BgpRIBKey for BgpEVPN {}
impl BgpRIBKey for BgpFlowSpec<BgpAddrV4> {}
pub struct BgpRIBIndex<K: Eq + Ord + Clone, T: BgpRIBKey> {
    pub idx: BTreeMap<K, BTreeSet<T>>,
}
impl<K: Eq + Ord + Clone, T: BgpRIBKey> Default for BgpRIBIndex<K, T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<K: Eq + Ord + Clone, T: BgpRIBKey> BgpRIBIndex<K, T> {
    pub fn new() -> BgpRIBIndex<K, T> {
        BgpRIBIndex::<K, T> {
            idx: BTreeMap::new(),
        }
    }
    pub fn set(&mut self, k: &K, t: &T) {
        if !self.idx.contains_key(k) {
            self.idx
                .insert(k.clone(), vec![t.clone()].into_iter().collect());
        } else {
            self.idx.get_mut(k).unwrap().insert(t.clone());
        }
    }
    pub fn clear(&mut self) {
        self.idx.clear();
    }
}
#[derive(Clone)]
pub struct ClonableIterator<'a, K, V> {
    pub itr: Arc<RefCell<Box<dyn Iterator<Item = (K, V)> + 'a>>>,
}
impl<'a, K, V> ClonableIterator<'a, K, V> {
    pub fn new(
        sitr: Arc<RefCell<Box<dyn Iterator<Item = (K, V)> + 'a>>>,
    ) -> ClonableIterator<'a, K, V> {
        ClonableIterator { itr: sitr }
    }
}
#[macro_export]
macro_rules! clone_iter {
    ( $x:expr ) => {
        ClonableIterator::new(Arc::new(std::cell::RefCell::new(Box::new($x))))
    };
}
impl<'a, K, V> std::iter::Iterator for ClonableIterator<'a, K, V> {
    type Item = (K, V);
    fn next(&mut self) -> Option<Self::Item> {
        self.itr.borrow_mut().next()
    }
}
#[derive(Clone)]
pub struct EmptyIter<'a, K: BgpRIBKey, T> {
    phantom: std::marker::PhantomData<(&'a K, &'a T)>,
}
impl<'a, K: BgpRIBKey, T> EmptyIter<'a, K, T> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}
impl<'a, K: BgpRIBKey, T> std::iter::Iterator for EmptyIter<'a, K, T> {
    type Item = (&'a K, &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
#[derive(Clone)]
pub struct MapFilter<'a, 'b, K: BgpRIBKey, T> {
    pub mapitr: ClonableIterator<'a, &'a K, &'a T>,
    pub flt: &'b BTreeSet<K>,
}

impl<'a, 'b, K: BgpRIBKey, T> MapFilter<'a, 'b, K, T> {
    pub fn new(srcitr: ClonableIterator<'a, &'a K, &'a T>, sflt: &'b BTreeSet<K>) -> Self {
        Self {
            mapitr: srcitr,
            flt: sflt,
        }
    }
}
impl<'a, 'b, K: BgpRIBKey, T> std::iter::Iterator for MapFilter<'a, 'b, K, T> {
    type Item = (&'a K, &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        for citr in self.mapitr.by_ref() {
            if self.flt.contains(citr.0) {
                return Some(citr);
            }
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpAttrHistory {
    pub items: BTreeMap<Timestamp, BgpAttrEntry>,
}
impl Default for BgpAttrHistory {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpAttrHistory {
    pub fn new() -> BgpAttrHistory {
        BgpAttrHistory {
            items: BTreeMap::new(),
        }
    }
    fn shrink_hist(&mut self, maxlen: usize) {
        while self.items.len() > maxlen {
            let q = match self.items.keys().next() {
                None => {
                    panic!("Unable to find key in history");
                }
                Some(q) => *q,
            };
            match self.items.remove(&q) {
                Some(_) => {}
                None => {
                    panic!("Unable to remove old record from history");
                }
            }
        }
    }
    pub fn get_last_attr(&self) -> Option<BgpAttrEntry> {
        self.items.iter().last().map(|v| (*v.1).clone())
    }
    pub fn insert(&mut self, when: Timestamp, entry: BgpAttrEntry) {
        self.items.insert(when, entry);
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpPathEntry {
    pub items: BTreeMap<BgpPathId, BgpAttrHistory>,
}
impl Default for BgpPathEntry {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpPathEntry {
    pub fn new() -> BgpPathEntry {
        BgpPathEntry {
            items: BTreeMap::new(),
        }
    }
    fn shrink_hist(&mut self, maxlen: usize) {
        self.items.iter_mut().for_each(|x| x.1.shrink_hist(maxlen));
    }
    pub fn get_last_attr(&self, path: BgpPathId) -> Option<BgpAttrEntry> {
        match self.items.get(&path) {
            None => None,
            Some(x) => x.get_last_attr(),
        }
    }
    pub fn insert(&mut self, path: BgpPathId, when: Timestamp, atr: BgpAttrEntry) {
        let pe = match self.items.get_mut(&path) {
            Some(e) => e,
            None => {
                self.items.insert(path, BgpAttrHistory::new());
                self.items.get_mut(&path).unwrap()
            }
        };
        pe.insert(when, atr);
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpSessionEntry {
    pub items: BTreeMap<BgpSessionId, BgpPathEntry>,
}
impl Default for BgpSessionEntry {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpSessionEntry {
    pub fn new() -> BgpSessionEntry {
        BgpSessionEntry {
            items: BTreeMap::new(),
        }
    }
    fn shrink_hist(&mut self, maxlen: usize) {
        self.items.iter_mut().for_each(|x| x.1.shrink_hist(maxlen))
    }
    pub fn get_last_attr(&self, sess: BgpSessionId, path: BgpPathId) -> Option<BgpAttrEntry> {
        match self.items.get(&sess) {
            None => None,
            Some(x) => x.get_last_attr(path),
        }
    }
    pub fn insert(
        &mut self,
        sess: BgpSessionId,
        path: BgpPathId,
        when: Timestamp,
        atr: BgpAttrEntry,
    ) {
        let pe = match self.items.get_mut(&sess) {
            Some(e) => e,
            None => {
                self.items.insert(sess, BgpPathEntry::new());
                self.items.get_mut(&sess).unwrap()
            }
        };
        pe.insert(path, when, atr)
    }
}
pub struct BgpRIBSafi<T: BgpRIBKey> {
    pub log_size: usize,
    pub history_mode: HistoryChangeMode,
    pub timeidx_granularity: u64,
    pub items: BTreeMap<T, BgpSessionEntry>,
    pub idx_aspath: BgpRIBIndex<BgpAS, T>,
    pub idx_community: BgpRIBIndex<BgpCommunity, T>,
    pub idx_extcommunity: BgpRIBIndex<BgpExtCommunity, T>,
    pub idx_changed: BgpRIBIndex<Timestamp, T>,
}
impl<T: BgpRIBKey> BgpRIBSafi<T> {
    pub fn new(logsize: usize, historymode: HistoryChangeMode) -> BgpRIBSafi<T> {
        BgpRIBSafi {
            log_size: logsize,
            history_mode: historymode,
            timeidx_granularity: 86400,
            items: BTreeMap::new(),
            idx_aspath: BgpRIBIndex::new(),
            idx_community: BgpRIBIndex::new(),
            idx_extcommunity: BgpRIBIndex::new(),
            idx_changed: BgpRIBIndex::new(),
        }
    }
    pub fn from_config(cfg: &SvcConfig) -> BgpRIBSafi<T> {
        BgpRIBSafi {
            log_size: cfg.historydepth,
            history_mode: cfg.historymode.clone(),
            timeidx_granularity: cfg.timeidx_granularity,
            items: BTreeMap::new(),
            idx_aspath: BgpRIBIndex::new(),
            idx_community: BgpRIBIndex::new(),
            idx_extcommunity: BgpRIBIndex::new(),
            idx_changed: BgpRIBIndex::new(),
        }
    }
    pub fn clear(&mut self) {
        self.items.clear();
        self.idx_aspath.clear();
        self.idx_community.clear();
        self.idx_extcommunity.clear();
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn assign(&mut self, items: BTreeMap<T, BgpSessionEntry>) {
        self.items = items;
        for (i, sess) in self.items.iter() {
            for (_, sess_ent) in sess.items.iter() {
                for (_, p_ent) in sess_ent.items.iter() {
                    for (chgd, rattre) in p_ent.items.iter() {
                        let rattr = &rattre.attrs;
                        //self.upd_idx(i,&rattre.attrs);
                        for aspathitem in rattr.aspath.value.iter() {
                            match aspathitem {
                                BgpASitem::Seq(v) => {
                                    for pi in v.value.iter() {
                                        self.idx_aspath.set(pi, i);
                                    }
                                }
                                BgpASitem::Set(v) => {
                                    for pi in v.value.iter() {
                                        self.idx_aspath.set(pi, i);
                                    }
                                }
                            }
                        }
                        for cmn in rattr.comms.value.iter() {
                            self.idx_community.set(cmn, i);
                        }
                        for cmn in rattr.extcomms.value.iter() {
                            // only route targets
                            if cmn.subtype == 2 {
                                self.idx_extcommunity.set(cmn, i);
                            }
                        }
                        let ch_idx = chgd.cut_millis(self.timeidx_granularity * 1000);
                        self.idx_changed.set(&ch_idx, i);
                    }
                }
            }
        }
    }
    /// Build filters chain
    pub fn get_iter<'b>(
        &'b self,
        filter: &RouteFilter,
        ribflt: Option<&RibResponseFilter>,
    ) -> ClonableIterator<'b, &'b T, &'b BgpSessionEntry> {
        let mut ret: ClonableIterator<'b, &'b T, &'b BgpSessionEntry> =
            clone_iter!(self.items.iter()); //ClonableIterator::new(Rc::new(self.items.iter()));
        for asp in filter.find_aspath_item().iter() {
            if let Some(f1) = self.idx_aspath.idx.get(&BgpAS::new(asp.value)) {
                ret = clone_iter!(MapFilter::new(ret, f1));
            } else {
                return clone_iter!(EmptyIter::new());
            };
        }
        for cmn in filter.find_community_item().iter() {
            if let Some(f1) = self.idx_community.idx.get(cmn) {
                ret = clone_iter!(MapFilter::new(ret, f1));
            } else {
                return clone_iter!(EmptyIter::new());
            };
        }
        for cmn in filter.find_extcommunity_item().iter() {
            if let Some(f1) = self.idx_extcommunity.idx.get(cmn) {
                ret = clone_iter!(MapFilter::new(ret, f1));
            } else {
                return clone_iter!(EmptyIter::new());
            };
        }
        if let Some(rf) = ribflt {
            match (rf.changed_after.as_ref(), rf.changed_before.as_ref()) {
                (Some(tf), Some(tt)) => {
                    if let Some(f1) = self
                        .idx_changed
                        .idx
                        .range(
                            &tf.cut_millis(self.timeidx_granularity * 1000)
                                ..&tt.cut_millis(self.timeidx_granularity * 1000),
                        )
                        .next()
                    {
                        ret = clone_iter!(MapFilter::new(ret, f1.1));
                    } else {
                        return clone_iter!(EmptyIter::new());
                    };
                }
                (Some(tf), None) => {
                    if let Some(f1) = self
                        .idx_changed
                        .idx
                        .range(&tf.cut_millis(self.timeidx_granularity * 1000)..)
                        .next()
                    {
                        ret = clone_iter!(MapFilter::new(ret, f1.1));
                    } else {
                        return clone_iter!(EmptyIter::new());
                    };
                }
                (None, Some(tt)) => {
                    if let Some(f1) = self
                        .idx_changed
                        .idx
                        .range(..&tt.cut_millis(self.timeidx_granularity * 1000))
                        .next()
                    {
                        ret = clone_iter!(MapFilter::new(ret, f1.1));
                    } else {
                        return clone_iter!(EmptyIter::new());
                    };
                }
                _ => {}
            }
        }
        ret
    }
    pub fn handle_withdraws_afi(&mut self, session: BgpSessionId, v: &[T]) {
        if v.is_empty() {
            return;
        }
        let now = Timestamp::now();
        for i in v.iter() {
            //TODO: indexes cleanup
            match self.items.get_mut(i) {
                None => {}
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    let lrec = match hist.get_last_attr(session, 0) {
                        None => continue,
                        Some(x) => x,
                    };
                    match self.history_mode {
                        HistoryChangeMode::EveryUpdate => {
                            hist.insert(
                                session,
                                0,
                                now,
                                BgpAttrEntry::new(false, lrec.attrs.clone(), i.getlabels()),
                            );
                        }
                        HistoryChangeMode::OnlyDiffer => {
                            if lrec.active {
                                hist.insert(
                                    session,
                                    0,
                                    now,
                                    BgpAttrEntry::new(false, lrec.attrs.clone(), i.getlabels()),
                                );
                            }
                        }
                    };
                }
            }
        }
    }
    pub fn handle_updates_afi(&mut self, session: BgpSessionId, v: &[T], rattr: Arc<BgpAttrs>) {
        if v.is_empty() {
            return;
        }
        let now = Timestamp::now();
        for i in v.iter() {
            for aspathitem in rattr.aspath.value.iter() {
                match aspathitem {
                    BgpASitem::Seq(v) => {
                        for pi in v.value.iter() {
                            self.idx_aspath.set(pi, i);
                        }
                    }
                    BgpASitem::Set(v) => {
                        for pi in v.value.iter() {
                            self.idx_aspath.set(pi, i);
                        }
                    }
                }
            }
            for cmn in rattr.comms.value.iter() {
                self.idx_community.set(cmn, i);
            }
            for cmn in rattr.extcomms.value.iter() {
                // only route targets
                if cmn.subtype == 2 {
                    self.idx_extcommunity.set(cmn, i);
                }
            }
            let cnow = now.cut_millis(self.timeidx_granularity * 1000);
            self.idx_changed.set(&cnow, i);
            let histrec = BgpAttrEntry::new(true, rattr.clone(), i.getlabels());
            match self.items.get_mut(i) {
                None => {
                    let mut hist = BgpSessionEntry::new();
                    hist.insert(session, 0, now, histrec);
                    self.items.insert(i.clone(), hist);
                }
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    match self.history_mode {
                        HistoryChangeMode::EveryUpdate => {
                            hist.insert(session, 0, now, histrec);
                        }
                        HistoryChangeMode::OnlyDiffer => {
                            match hist.get_last_attr(session, 0) {
                                None => {
                                    hist.insert(session, 0, now, histrec);
                                }
                                Some(lrec) => {
                                    if !lrec.active || lrec.attrs != histrec.attrs {
                                        hist.insert(session, 0, now, histrec);
                                    }
                                }
                            };
                        }
                    };
                }
            };
        }
    }
    pub fn handle_withdraws_afi_pathid(&mut self, session: BgpSessionId, v: &[WithPathId<T>]) {
        if v.is_empty() {
            return;
        }
        let now = Timestamp::now();
        for i in v.iter() {
            //TODO: indexes cleanup
            match self.items.get_mut(&i.nlri) {
                None => {}
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    let lrec = match hist.get_last_attr(session, i.pathid) {
                        None => continue,
                        Some(x) => x,
                    };
                    match self.history_mode {
                        HistoryChangeMode::EveryUpdate => {
                            hist.insert(
                                session,
                                i.pathid,
                                now,
                                BgpAttrEntry::new(false, lrec.attrs.clone(), i.nlri.getlabels()),
                            );
                        }
                        HistoryChangeMode::OnlyDiffer => {
                            if lrec.active {
                                hist.insert(
                                    session,
                                    i.pathid,
                                    now,
                                    BgpAttrEntry::new(
                                        false,
                                        lrec.attrs.clone(),
                                        i.nlri.getlabels(),
                                    ),
                                );
                            }
                        }
                    };
                }
            }
        }
    }
    pub fn handle_updates_afi_pathid(
        &mut self,
        session: BgpSessionId,
        v: &[WithPathId<T>],
        rattr: Arc<BgpAttrs>,
    ) {
        if v.is_empty() {
            return;
        }
        for i in v.iter() {
            for aspathitem in rattr.aspath.value.iter() {
                match aspathitem {
                    BgpASitem::Seq(v) => {
                        for pi in v.value.iter() {
                            self.idx_aspath.set(pi, &i.nlri);
                        }
                    }
                    BgpASitem::Set(v) => {
                        for pi in v.value.iter() {
                            self.idx_aspath.set(pi, &i.nlri);
                        }
                    }
                }
            }
            for cmn in rattr.comms.value.iter() {
                self.idx_community.set(cmn, &i.nlri);
            }
            for cmn in rattr.extcomms.value.iter() {
                // only route targets
                if cmn.subtype == 2 {
                    self.idx_extcommunity.set(cmn, &i.nlri);
                }
            }
            let histrec = BgpAttrEntry::new(true, rattr.clone(), i.nlri.getlabels());
            let now = Timestamp::now();
            let cnow = now.cut_millis(self.timeidx_granularity * 1000);
            self.idx_changed.set(&cnow, &i.nlri);
            match self.items.get_mut(&i.nlri) {
                None => {
                    let mut hist = BgpSessionEntry::new();
                    hist.insert(session, i.pathid, now, histrec);
                    self.items.insert(i.nlri.clone(), hist);
                }
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    match self.history_mode {
                        HistoryChangeMode::EveryUpdate => {
                            hist.insert(session, i.pathid, now, histrec);
                        }
                        HistoryChangeMode::OnlyDiffer => {
                            match hist.get_last_attr(session, i.pathid) {
                                None => {
                                    hist.insert(session, i.pathid, now, histrec);
                                }
                                Some(lrec) => {
                                    if !lrec.active || lrec.attrs != histrec.attrs {
                                        hist.insert(session, i.pathid, now, histrec);
                                    }
                                }
                            };
                        }
                    };
                }
            };
        }
    }
}
#[derive(Clone)]
pub enum BgpEvent {
    Update(BgpSessionId, Arc<BgpAttrs>, Arc<BgpAddrs>),
    Withdraw(BgpSessionId, Arc<BgpAddrs>),
}
pub struct BgpRIB {
    pub pathes: RibItemStore<BgpASpath>,
    pub comms: RibItemStore<BgpCommunityList>,
    pub lcomms: RibItemStore<BgpLargeCommunityList>,
    pub extcomms: RibItemStore<BgpExtCommunityList>,
    pub clusters: RibItemStore<BgpClusterList>,
    pub pmsi_ta_s: RibItemStore<BgpPMSITunnel>,
    pub attrs: RibItemStore<BgpAttrs>,
    pub ipv4u: BgpRIBSafi<BgpAddrV4>,
    pub ipv4m: BgpRIBSafi<BgpAddrV4>,
    pub ipv4lu: BgpRIBSafi<Labeled<BgpAddrV4>>,
    pub vpnv4u: BgpRIBSafi<Labeled<WithRd<BgpAddrV4>>>,
    pub vpnv4m: BgpRIBSafi<Labeled<WithRd<BgpAddrV4>>>,
    pub ipv6u: BgpRIBSafi<BgpAddrV6>,
    pub ipv6lu: BgpRIBSafi<Labeled<BgpAddrV6>>,
    pub vpnv6u: BgpRIBSafi<Labeled<WithRd<BgpAddrV6>>>,
    pub vpnv6m: BgpRIBSafi<Labeled<WithRd<BgpAddrV6>>>,
    pub l2vpls: BgpRIBSafi<BgpAddrL2>,
    pub mvpn: BgpRIBSafi<BgpMVPN>,
    pub evpn: BgpRIBSafi<BgpEVPN>,
    pub fs4u: BgpRIBSafi<BgpFlowSpec<BgpAddrV4>>,
    pub ipv4mdt: BgpRIBSafi<WithRd<BgpMdtV4>>,
    pub ipv6mdt: BgpRIBSafi<WithRd<BgpMdtV6>>,
    pub cnt_updates: u64,
    pub cnt_withdraws: u64,
    pub events: broadcast::Sender<BgpEvent>,
    cnt_purge: u64,
    purge_after_withdraws: u64,
    purge_every: chrono::Duration,
    purged: Timestamp,
    snapshot_file: Option<String>,
    snapshot_every: Option<chrono::Duration>,
    snapshot_saved: Timestamp,
}
unsafe impl Sync for BgpRIB {}
unsafe impl Send for BgpRIB {}

impl BgpRIB {
    pub fn new(cfg: &SvcConfig) -> BgpRIB {
        let now = Timestamp::now();
        let (tx, _) = broadcast::channel(2);
        BgpRIB {
            pathes: RibItemStore::new(),
            comms: RibItemStore::new(),
            lcomms: RibItemStore::new(),
            extcomms: RibItemStore::new(),
            clusters: RibItemStore::new(),
            pmsi_ta_s: RibItemStore::new(),
            attrs: RibItemStore::new(),
            ipv4u: BgpRIBSafi::from_config(cfg),
            ipv4m: BgpRIBSafi::from_config(cfg),
            ipv4lu: BgpRIBSafi::from_config(cfg),
            vpnv4u: BgpRIBSafi::from_config(cfg),
            vpnv4m: BgpRIBSafi::from_config(cfg),
            ipv6u: BgpRIBSafi::from_config(cfg),
            ipv6lu: BgpRIBSafi::from_config(cfg),
            vpnv6u: BgpRIBSafi::from_config(cfg),
            vpnv6m: BgpRIBSafi::from_config(cfg),
            l2vpls: BgpRIBSafi::from_config(cfg),
            mvpn: BgpRIBSafi::from_config(cfg),
            evpn: BgpRIBSafi::from_config(cfg),
            fs4u: BgpRIBSafi::from_config(cfg),
            ipv4mdt: BgpRIBSafi::from_config(cfg),
            ipv6mdt: BgpRIBSafi::from_config(cfg),
            cnt_updates: 0,
            cnt_withdraws: 0,
            events: tx,
            cnt_purge: 0,
            purge_after_withdraws: cfg.purge_after_withdraws,
            purge_every: cfg.purge_every,
            purged: now,
            snapshot_file: cfg.snapshot_file.clone(),
            snapshot_every: cfg.snapshot_every,
            snapshot_saved: now,
        }
    }
    pub fn purge(&mut self) {
        self.attrs.purge();
        self.clusters.purge();
        self.extcomms.purge();
        self.lcomms.purge();
        self.comms.purge();
        self.pathes.purge();
        if self.purge_after_withdraws > 0 {
            self.cnt_purge = self.cnt_withdraws / self.purge_after_withdraws;
        };
        self.purged = Timestamp::now();
        if let Some(se) = self.snapshot_every.as_ref() {
            if (chrono::Local::now() - *(self.snapshot_saved.deref())) > *se {
                if let Err(e) = self.store_snapshot() {
                    warn!("store_snapshot error: {}", e);
                }
                self.snapshot_saved = Timestamp::now();
            }
        }
    }
    pub fn needs_purge(&self) -> bool {
        if self.purge_after_withdraws > 0
            && (self.cnt_withdraws / self.purge_after_withdraws) != self.cnt_purge
        {
            return true;
        }
        (chrono::Local::now() - *(self.purged.deref())) > self.purge_every
    }
    fn write_snapshot<W>(&self, mut file: W) -> Result<(), ciborium::ser::Error<std::io::Error>>
    where
        W: std::io::Write,
    {
        ciborium::ser::into_writer(&self.ipv4u.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv4m.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv4lu.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.vpnv4u.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.vpnv4m.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv6u.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv6lu.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.vpnv6u.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.vpnv6m.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.l2vpls.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.mvpn.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.evpn.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.fs4u.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv4mdt.items, file.by_ref())?;
        ciborium::ser::into_writer(&self.ipv6mdt.items, file.by_ref())?;
        Ok(())
    }
    pub async fn shutdown(&self) {
        if let Err(e) = self.store_snapshot() {
            warn!("store_snapshot error on shutdown: {}", e);
        }
    }
    pub fn store_snapshot(&self) -> std::io::Result<()> {
        if self.snapshot_file.is_none() {
            return Ok(());
        }
        let ftmp = self.snapshot_file.as_ref().unwrap().clone() + ".tmp";
        {
            let file = BufWriter::with_capacity(4096, std::fs::File::create(&ftmp)?);
            info!(
                "Creating snapshot: {}",
                self.snapshot_file.as_ref().unwrap()
            );
            if let Err(e) = self.write_snapshot(file) {
                warn!("Unable to save snapshot: {}", e);
                let _ = std::fs::remove_file(&ftmp);
                return Ok(());
            }
        }
        let _ = std::fs::remove_file(self.snapshot_file.as_ref().unwrap());
        std::fs::rename(&ftmp, self.snapshot_file.as_ref().unwrap())?;
        Ok(())
    }
    pub fn clear(&mut self) {
        self.ipv4u.clear();
        self.ipv4m.clear();
        self.ipv4lu.clear();
        self.vpnv4u.clear();
        self.vpnv4m.clear();
        self.ipv6u.clear();
        self.ipv6lu.clear();
        self.vpnv6u.clear();
        self.vpnv6m.clear();
        self.l2vpls.clear();
        self.mvpn.clear();
        self.evpn.clear();
        self.fs4u.clear();
        self.ipv4mdt.clear();
        self.ipv6mdt.clear();
        self.attrs.clear();
        self.clusters.clear();
        self.extcomms.clear();
        self.lcomms.clear();
        self.comms.clear();
        self.pathes.clear();
    }
    pub fn load_snapshot<P: AsRef<std::path::Path>>(
        cfg: &SvcConfig,
        fnm: P,
    ) -> Result<BgpRIB, Box<dyn std::error::Error>> {
        if cfg.snapshot_file.is_none() {
            return Ok(BgpRIB::new(cfg));
        }
        info!("Loading snapshot: {}", cfg.snapshot_file.as_ref().unwrap());
        let mut fl = BufReader::new(std::fs::File::open(fnm)?);
        rib_set(BgpRIB::new(cfg));
        let ipv4u = ciborium::de::from_reader(&mut fl)?;
        let ipv4m = ciborium::de::from_reader(&mut fl)?;
        let ipv4lu = ciborium::de::from_reader(&mut fl)?;
        let vpnv4u = ciborium::de::from_reader(&mut fl)?;
        let vpnv4m = ciborium::de::from_reader(&mut fl)?;
        let ipv6u = ciborium::de::from_reader(&mut fl)?;
        let ipv6lu = ciborium::de::from_reader(&mut fl)?;
        let vpnv6u = ciborium::de::from_reader(&mut fl)?;
        let vpnv6m = ciborium::de::from_reader(&mut fl)?;
        let l2vpls = ciborium::de::from_reader(&mut fl)?;
        let mvpn = ciborium::de::from_reader(&mut fl)?;
        let evpn = ciborium::de::from_reader(&mut fl)?;
        let fs4u = ciborium::de::from_reader(&mut fl)?;
        let ipv4mdt = ciborium::de::from_reader(&mut fl)?;
        let ipv6mdt = ciborium::de::from_reader(&mut fl)?;
        let mut rib = rib_take();
        rib.ipv4u.assign(ipv4u);
        rib.ipv4m.assign(ipv4m);
        rib.ipv4lu.assign(ipv4lu);
        rib.vpnv4u.assign(vpnv4u);
        rib.vpnv4m.assign(vpnv4m);
        rib.ipv6u.assign(ipv6u);
        rib.ipv6lu.assign(ipv6lu);
        rib.vpnv6u.assign(vpnv6u);
        rib.vpnv6m.assign(vpnv6m);
        rib.l2vpls.assign(l2vpls);
        rib.mvpn.assign(mvpn);
        rib.evpn.assign(evpn);
        rib.fs4u.assign(fs4u);
        rib.ipv4mdt.assign(ipv4mdt);
        rib.ipv6mdt.assign(ipv6mdt);
        Ok(rib)
    }
    pub fn handle_withdraws(&mut self, session: BgpSessionId, withdraws: BgpAddrs) {
        match &withdraws {
            BgpAddrs::IPV4U(v) => self.ipv4u.handle_withdraws_afi(session, v),
            BgpAddrs::IPV4M(v) => self.ipv4m.handle_withdraws_afi(session, v),
            BgpAddrs::IPV4LU(v) => self.ipv4lu.handle_withdraws_afi(session, v),
            BgpAddrs::VPNV4U(v) => self.vpnv4u.handle_withdraws_afi(session, v),
            BgpAddrs::VPNV4M(v) => self.vpnv4m.handle_withdraws_afi(session, v),
            BgpAddrs::IPV6U(v) => self.ipv6u.handle_withdraws_afi(session, v),
            BgpAddrs::IPV6LU(v) => self.ipv6lu.handle_withdraws_afi(session, v),
            BgpAddrs::VPNV6U(v) => self.vpnv6u.handle_withdraws_afi(session, v),
            BgpAddrs::VPNV6M(v) => self.vpnv6m.handle_withdraws_afi(session, v),
            BgpAddrs::L2VPLS(v) => self.l2vpls.handle_withdraws_afi(session, v),
            BgpAddrs::MVPN(v) => self.mvpn.handle_withdraws_afi(session, v),
            BgpAddrs::EVPN(v) => self.evpn.handle_withdraws_afi(session, v),
            BgpAddrs::FS4U(v) => self.fs4u.handle_withdraws_afi(session, v),
            BgpAddrs::IPV4UP(v) => self.ipv4u.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::IPV4MP(v) => self.ipv4m.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::IPV4LUP(v) => self.ipv4lu.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::VPNV4UP(v) => self.vpnv4u.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::VPNV4MP(v) => self.vpnv4m.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::IPV6UP(v) => self.ipv6u.handle_withdraws_afi_pathid(session, v),
            //BgpAddrs::IPV6MP(v) => self.ipv6m.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::IPV6LUP(v) => self.ipv6lu.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::VPNV6UP(v) => self.vpnv6u.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::VPNV6MP(v) => self.vpnv6m.handle_withdraws_afi_pathid(session, v),
            BgpAddrs::IPV4MDT(v) => self.ipv4mdt.handle_withdraws_afi(session, v),
            BgpAddrs::IPV6MDT(v) => self.ipv6mdt.handle_withdraws_afi(session, v),
            _ => {}
        };
        if self.events.receiver_count() > 0 {
            if let Err(e) = self
                .events
                .send(BgpEvent::Withdraw(session, Arc::new(withdraws)))
            {
                warn!("Publish withdraw event error: {}", e);
            }
        }
    }
    pub fn handle_updates(
        &mut self,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        updates: BgpAddrs,
    ) {
        let ra = rattr.clone();
        match &updates {
            BgpAddrs::IPV4U(v) => self.ipv4u.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV4M(v) => self.ipv4m.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV4LU(v) => self.ipv4lu.handle_updates_afi(session, v, rattr),
            BgpAddrs::VPNV4U(v) => self.vpnv4u.handle_updates_afi(session, v, rattr),
            BgpAddrs::VPNV4M(v) => self.vpnv4m.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV6U(v) => self.ipv6u.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV6LU(v) => self.ipv6lu.handle_updates_afi(session, v, rattr),
            BgpAddrs::VPNV6U(v) => self.vpnv6u.handle_updates_afi(session, v, rattr),
            BgpAddrs::VPNV6M(v) => self.vpnv6m.handle_updates_afi(session, v, rattr),
            BgpAddrs::L2VPLS(v) => self.l2vpls.handle_updates_afi(session, v, rattr),
            BgpAddrs::MVPN(v) => self.mvpn.handle_updates_afi(session, v, rattr),
            BgpAddrs::EVPN(v) => self.evpn.handle_updates_afi(session, v, rattr),
            BgpAddrs::FS4U(v) => self.fs4u.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV4UP(v) => self.ipv4u.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV4MP(v) => self.ipv4m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV4LUP(v) => self.ipv4lu.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::VPNV4UP(v) => self.vpnv4u.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::VPNV4MP(v) => self.vpnv4m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV6UP(v) => self.ipv6u.handle_updates_afi_pathid(session, v, rattr),
            //BgpAddrs::IPV6MP(v) => self.ipv6m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV6LUP(v) => self.ipv6lu.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::VPNV6UP(v) => self.vpnv6u.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::VPNV6MP(v) => self.vpnv6m.handle_updates_afi_pathid(session, v, rattr),
            BgpAddrs::IPV4MDT(v) => self.ipv4mdt.handle_updates_afi(session, v, rattr),
            BgpAddrs::IPV6MDT(v) => self.ipv6mdt.handle_updates_afi(session, v, rattr),
            _ => {}
        };
        if self.events.receiver_count() > 0 {
            if let Err(e) = self
                .events
                .send(BgpEvent::Update(session, ra, Arc::new(updates)))
            {
                warn!("Publish update event error: {}", e);
            }
        }
    }
    fn register_shared<T: Clone + Eq + Ord + std::hash::Hash + std::fmt::Debug>(
        hset: &mut RibItemStore<T>,
        item: &T,
    ) -> Result<Arc<T>, Box<dyn std::error::Error>> {
        hset.get(Arc::new(item.clone()))
    }
    pub fn handle_update(
        &mut self,
        sessionid: BgpSessionId,
        upd: BgpUpdateMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut attr = BgpAttrs {
            origin: match upd.get_attr_origin() {
                None => {
                    //return Err(Box::new(BgpError::static_str("missing origin")));
                    BgpAttrOrigin::Incomplete
                }
                Some(n) => n.value,
            },
            nexthop: match upd.get_attr_nexthop() {
                None => BgpAddr::None,
                Some(n) => match n.value {
                    std::net::IpAddr::V4(v) => BgpAddr::V4(v),
                    std::net::IpAddr::V6(v) => BgpAddr::V6(v),
                },
            },
            aspath: match upd.get_attr_aspath() {
                None => BgpRIB::register_shared(&mut self.pathes, &BgpASpath::new()),
                Some(n) => BgpRIB::register_shared(&mut self.pathes, n),
            }?,
            comms: match upd.get_attr_communitylist() {
                None => BgpRIB::register_shared(&mut self.comms, &BgpCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.comms, n),
            }?,
            lcomms: match upd.get_attr_largecommunitylist() {
                None => BgpRIB::register_shared(&mut self.lcomms, &BgpLargeCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.lcomms, n),
            }?,
            extcomms: match upd.get_attr_extcommunitylist() {
                None => BgpRIB::register_shared(&mut self.extcomms, &BgpExtCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.extcomms, n),
            }?,
            med: None,
            localpref: None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
        };
        for i in upd.attrs.iter() {
            match i {
                BgpAttrItem::MED(n) => {
                    attr.med = Some(n.value);
                }
                BgpAttrItem::LocalPref(n) => {
                    attr.localpref = Some(n.value);
                }
                BgpAttrItem::AtomicAggregate(n) => {
                    attr.atomicaggregate = Some(n.value);
                }
                BgpAttrItem::AggregatorAS(n) => {
                    attr.aggregatoras = Some(n.clone());
                }
                BgpAttrItem::OriginatorID(n) => {
                    attr.originator = Some(n.value);
                }
                BgpAttrItem::ClusterList(n) => {
                    attr.clusterlist = Some(self.clusters.get(Arc::new(n.clone()))?);
                }
                BgpAttrItem::PMSITunnel(n) => {
                    attr.pmsi_ta = Some(self.pmsi_ta_s.get(Arc::new(n.clone()))?);
                }
                BgpAttrItem::Unknown(_) => {
                    warn!("{}\tBGP Unknown: {:?}", Timestamp::now(), upd);
                }
                _ => {}
            }
        }
        //let adr=bgp::BgpAddrV4::new(std::net::Ipv4Addr::new(0,0,0,0),32);
        let rattr = BgpRIB::register_shared(&mut self.attrs, &attr)?;
        let mut updates_count: usize = upd.updates.len();
        let mut withdraws_count: usize = upd.withdraws.len();
        self.handle_withdraws(sessionid, upd.withdraws);
        self.handle_updates(sessionid, rattr.clone(), upd.updates);
        for i in upd.attrs.into_iter() {
            match i {
                BgpAttrItem::MPUpdates(n) => {
                    let cattr = if n.nexthop == attr.nexthop {
                        rattr.clone()
                    } else {
                        attr.nexthop = n.nexthop.clone();
                        BgpRIB::register_shared(&mut self.attrs, &attr)?
                    };
                    updates_count += n.addrs.len();
                    self.handle_updates(sessionid, cattr.clone(), n.addrs);
                }
                BgpAttrItem::MPWithdraws(n) => {
                    withdraws_count += n.addrs.len();
                    self.handle_withdraws(sessionid, n.addrs);
                }
                _ => {}
            }
        }
        self.cnt_updates += updates_count as u64;
        self.cnt_withdraws += withdraws_count as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ribitemstore() {
        let mut teststore = RibItemStore::<u32>::new();
        assert_eq!(teststore.len(), 0);
        {
            let _rs = teststore.get(Arc::new(12));
            assert_eq!(teststore.len(), 1);
            teststore.purge();
            assert_eq!(teststore.len(), 1);
        }
        teststore.purge();
        assert_eq!(teststore.len(), 0);
    }
}
