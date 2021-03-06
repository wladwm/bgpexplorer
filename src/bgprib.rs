use crate::ribfilter::RouteFilter;
use chrono::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;
use std::cell::RefCell;
use zettabgp::prelude::*;
use crate::bgpsvc::BgpSessionId;
use crate::config::*;
use std::iter::Iterator;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct BgpAttrs {
    pub origin: BgpAttrOrigin,
    pub nexthop: BgpAddr,
    pub aspath: Rc<BgpASpath>,
    pub comms: Rc<BgpCommunityList>,
    pub lcomms: Rc<BgpLargeCommunityList>,
    pub extcomms: Rc<BgpExtCommunityList>,
    pub med: Option<u32>,
    pub localpref: Option<u32>,
    pub atomicaggregate: Option<std::net::IpAddr>,
    pub aggregatoras: Option<BgpAggregatorAS>,
    pub originator: Option<std::net::IpAddr>,
    pub clusterlist: Option<Rc<BgpClusterList>>,
    pub pmsi_ta: Option<Rc<BgpPMSITunnel>>,
}
impl BgpAttrs {
    pub fn new() -> BgpAttrs {
        BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            aspath: Rc::new(BgpASpath::new()),
            comms: Rc::new(BgpCommunityList::new()),
            lcomms: Rc::new(BgpLargeCommunityList::new()),
            extcomms: Rc::new(BgpExtCommunityList::new()),
            med: None,
            localpref: None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
        }
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RibItem<T: std::hash::Hash + Eq + Ord> {
    pub item: std::rc::Rc<T>,
}
impl<T: std::hash::Hash + Eq + Ord> RibItem<T> {
    pub fn fromrc(itm: &std::rc::Rc<T>) -> RibItem<T> {
        RibItem { item: itm.clone() }
    }
    pub fn is_empty(&self) -> bool {
        Rc::strong_count(&self.item) < 2
    }
}
pub struct RibItemStore<T: std::hash::Hash + Eq + Ord> {
    pub items: HashSet<RibItem<T>>,
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
    pub fn get(&mut self, item: Rc<T>) -> Result<Rc<T>, Box<dyn std::error::Error>> {
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
            self.idx.get_mut(&k).unwrap().insert(t.clone());
        }
    }
}
#[derive(Clone)]
pub struct ClonableIterator<'a,K,V> {
    pub itr: Rc<RefCell<Box<dyn Iterator<Item=(K,V)>+'a>>>,
}
impl<'a,K,V> ClonableIterator<'a,K,V> {
    pub fn new(sitr:Rc<RefCell<Box<dyn Iterator<Item=(K,V)>+'a>>>) -> ClonableIterator<'a,K,V> {
        ClonableIterator {
            itr: sitr
        }
    }
}
#[macro_export]
macro_rules! clone_iter {
    ( $x:expr ) => {
            ClonableIterator::new(Rc::new(std::cell::RefCell::new(Box::new($x))))
    }
}
impl<'a,K,V> std::iter::Iterator for ClonableIterator<'a,K,V> {
    type Item = (K,V);
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
    pub mapitr: ClonableIterator<'a,&'a K,&'a T>,
    pub flt: &'b BTreeSet<K>,
}

impl<'a, 'b, K: BgpRIBKey, T> MapFilter<'a, 'b, K, T> {
    pub fn new(
        srcitr: ClonableIterator<'a,&'a K,&'a T>,
        sflt: &'b BTreeSet<K>,
    ) -> Self {
        Self {
            mapitr: srcitr,
            flt: sflt,
        }
    }
}
impl<'a, 'b, K: BgpRIBKey, T> std::iter::Iterator for MapFilter<'a, 'b, K, T> {
    type Item = (&'a K, &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(citr) = self.mapitr.next() {
            if self.flt.contains(citr.0) {
                return Some(citr);
            }
        }
        None
    }
}
#[derive(Debug,Clone)]
pub struct BgpAttrEntry {
    pub active: bool,
    pub attrs: Rc<BgpAttrs>,
    pub labels: Option<MplsLabels>,
}
impl BgpAttrEntry {
    pub fn new(act: bool, atr: Rc<BgpAttrs>, lbl: Option<MplsLabels>) -> BgpAttrEntry {
        BgpAttrEntry {
            active: act,
            attrs: atr,
            labels: lbl,
        }
    }
}
#[derive(Debug)]
pub struct BgpAttrHistory {
    pub items: BTreeMap<DateTime<Local>, BgpAttrEntry>,
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
                Some(q) => q.clone(),
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
        match self.items.iter().last() {
            None => None,
            Some(v) => Some((*v.1).clone()),
        }
    }
    pub fn insert(&mut self,when:DateTime<Local>,entry:BgpAttrEntry) {
        self.items.insert(when,entry);
    }
}
#[derive(Debug)]
pub struct BgpPathEntry {
    pub items: BTreeMap<BgpPathId,BgpAttrHistory>
}
impl BgpPathEntry {
    pub fn new() -> BgpPathEntry {
        BgpPathEntry {
            items: BTreeMap::new(),
        }
    }
    fn shrink_hist(&mut self, maxlen: usize) {
        self.items.iter_mut().for_each(|x|{x.1.shrink_hist(maxlen)});
    }
    pub fn get_last_attr(&self,path:BgpPathId) -> Option<BgpAttrEntry> {
        match self.items.get(&path) {
            None => None,
            Some(x) => x.get_last_attr()
        }
    }
    pub fn insert(&mut self,path:BgpPathId,when:DateTime<Local>,atr:BgpAttrEntry) {
        let pe=match self.items.get_mut(&path) {
            Some(e) => e,
            None => {
                self.items.insert(path, BgpAttrHistory::new());
                self.items.get_mut(&path).unwrap()
            }
        };
        pe.insert(when,atr);
    }
}
#[derive(Debug)]
pub struct BgpSessionEntry {
    pub items: BTreeMap<BgpSessionId,BgpPathEntry>
}
impl BgpSessionEntry {
    pub fn new() -> BgpSessionEntry {
        BgpSessionEntry {
            items: BTreeMap::new(),
        }
    }
    fn shrink_hist(&mut self, maxlen: usize) {
        self.items.iter_mut().for_each(|x| {x.1.shrink_hist(maxlen)})
    }
    pub fn get_last_attr(&self,sess:BgpSessionId,path:BgpPathId) -> Option<BgpAttrEntry> {
        match self.items.get(&sess) {
            None => None,
            Some(x) => x.get_last_attr(path)
        }
    }
    pub fn insert(&mut self,sess:BgpSessionId,path:BgpPathId,when:DateTime<Local>,atr:BgpAttrEntry) {
        let pe=match self.items.get_mut(&sess) {
            Some(e) => e,
            None => {
                self.items.insert(sess, BgpPathEntry::new());
                self.items.get_mut(&sess).unwrap()
            }
        };
        pe.insert(path,when,atr)
    }
}
pub struct BgpRIBSafi<T: BgpRIBKey> {
    pub log_size: usize,
    pub history_mode: HistoryChangeMode,
    pub items: BTreeMap<T, BgpSessionEntry>,
    pub idx_aspath: BgpRIBIndex<BgpAS, T>,
    pub idx_community: BgpRIBIndex<BgpCommunity, T>,
    pub idx_extcommunity: BgpRIBIndex<BgpExtCommunity, T>,
}
impl<T: BgpRIBKey> BgpRIBSafi<T> {
    pub fn new(logsize: usize, historymode: HistoryChangeMode) -> BgpRIBSafi<T> {
        BgpRIBSafi {
            log_size: logsize,
            history_mode: historymode,
            items: BTreeMap::new(),
            idx_aspath: BgpRIBIndex::new(),
            idx_community: BgpRIBIndex::new(),
            idx_extcommunity: BgpRIBIndex::new(),
        }
    }
    pub fn from_config(cfg: &SvcConfig) -> BgpRIBSafi<T> {
        BgpRIBSafi {
            log_size: cfg.historydepth,
            history_mode: cfg.historymode.clone(),
            items: BTreeMap::new(),
            idx_aspath: BgpRIBIndex::new(),
            idx_community: BgpRIBIndex::new(),
            idx_extcommunity: BgpRIBIndex::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    /// Build filters chain
    pub fn get_iter<'b>(
        &'b self,
        filter: &RouteFilter,
    ) -> ClonableIterator<'b,&'b T,&'b BgpSessionEntry> {
        let mut ret: ClonableIterator<'b,&'b T,&'b BgpSessionEntry> = clone_iter!(self.items.iter());//ClonableIterator::new(Rc::new(self.items.iter()));
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
        ret
    }
    pub fn handle_withdraws_afi(&mut self, session: BgpSessionId, v: &Vec<T>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
            //TODO: indexes cleanup
            match self.items.get_mut(&i) {
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
    pub fn handle_updates_afi(&mut self, session: BgpSessionId, v: Vec<T>, rattr: Rc<BgpAttrs>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
            for aspathitem in rattr.aspath.value.iter() {
                self.idx_aspath.set(aspathitem, &i);
            }
            for cmn in rattr.comms.value.iter() {
                self.idx_community.set(cmn, &i);
            }
            for cmn in rattr.extcomms.value.iter() {
                // only route targets
                if cmn.subtype == 2 {
                    self.idx_extcommunity.set(cmn, &i);
                }
            }
            let histrec = BgpAttrEntry::new(true, rattr.clone(), i.getlabels());
            match self.items.get_mut(&i) {
                None => {
                    let mut hist = BgpSessionEntry::new();
                    hist.insert(session, 0, now, histrec);
                    self.items.insert(i, hist);
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
    pub fn handle_withdraws_afi_pathid(&mut self, session: BgpSessionId, v: &Vec<WithPathId<T>>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
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
                                session, i.pathid,
                                now,
                                BgpAttrEntry::new(false, lrec.attrs.clone(), i.nlri.getlabels()),
                            );
                        }
                        HistoryChangeMode::OnlyDiffer => {
                            if lrec.active {
                                hist.insert(
                                    session, i.pathid,
                                    now,
                                    BgpAttrEntry::new(false, lrec.attrs.clone(), i.nlri.getlabels()),
                                );
                            }
                        }
                    };
                }
            }
        }
    }
    pub fn handle_updates_afi_pathid(&mut self, session: BgpSessionId, v: Vec<WithPathId<T>>, rattr: Rc<BgpAttrs>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
            for aspathitem in rattr.aspath.value.iter() {
                self.idx_aspath.set(aspathitem, &i.nlri);
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
            match self.items.get_mut(&i.nlri) {
                None => {
                    let mut hist = BgpSessionEntry::new();
                    hist.insert(session, i.pathid, now, histrec);
                    self.items.insert(i.nlri, hist);
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
    pub cnt_updates: u64,
    pub cnt_withdraws: u64,
    cnt_purge: u64,
    purge_after_withdraws: u64,
    purge_every: chrono::Duration,
    purged: chrono::DateTime<Local>,
}
unsafe impl Sync for BgpRIB {}
unsafe impl Send for BgpRIB {}

impl BgpRIB {
    pub fn new(cfg: &SvcConfig) -> BgpRIB {
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
            cnt_updates: 0,
            cnt_withdraws: 0,
            cnt_purge: 0,
            purge_after_withdraws: cfg.purge_after_withdraws,
            purge_every: cfg.purge_every,
            purged: chrono::Local::now(),
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
        self.purged = chrono::Local::now();
    }
    pub fn handle_withdraws(&mut self, session: BgpSessionId, withdraws: &BgpAddrs) {
        match withdraws {
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
            _ => {}
        };
    }
    pub fn handle_updates(&mut self, session: BgpSessionId, rattr: Rc<BgpAttrs>, updates: BgpAddrs) {
        match updates {
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
            _ => {}
        };
    }
    fn register_shared<T: Clone + Eq + Ord + std::hash::Hash + std::fmt::Debug>(
        hset: &mut RibItemStore<T>,
        item: &T,
    ) -> Result<Rc<T>, Box<dyn std::error::Error>> {
        hset.get(std::rc::Rc::new(item.clone()))
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
                Some(n) => BgpRIB::register_shared(&mut self.pathes, &n),
            }?,
            comms: match upd.get_attr_communitylist() {
                None => BgpRIB::register_shared(&mut self.comms, &BgpCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.comms, &n),
            }?,
            lcomms: match upd.get_attr_largecommunitylist() {
                None => BgpRIB::register_shared(&mut self.lcomms, &BgpLargeCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.lcomms, &n),
            }?,
            extcomms: match upd.get_attr_extcommunitylist() {
                None => BgpRIB::register_shared(&mut self.extcomms, &BgpExtCommunityList::new()),
                Some(n) => BgpRIB::register_shared(&mut self.extcomms, &n),
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
                    attr.clusterlist = Some(self.clusters.get(std::rc::Rc::new(n.clone()))?);
                }
                BgpAttrItem::PMSITunnel(n) => {
                    attr.pmsi_ta = Some(self.pmsi_ta_s.get(std::rc::Rc::new(n.clone()))?);
                }
                BgpAttrItem::Unknown(_) => {
                    eprintln!("{}\tBGP Unknown: {:?}", Local::now(), upd);
                }
                _ => {}
            }
        }
        //let adr=bgp::BgpAddrV4::new(std::net::Ipv4Addr::new(0,0,0,0),32);
        let rattr = BgpRIB::register_shared(&mut self.attrs, &attr)?;
        let mut updates_count: usize = upd.updates.len();
        let mut withdraws_count: usize = upd.withdraws.len();
        self.handle_withdraws(sessionid,&upd.withdraws);
        self.handle_updates(sessionid,rattr.clone(),upd.updates);
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
                    self.handle_updates(sessionid,cattr.clone(), n.addrs);
                }
                BgpAttrItem::MPWithdraws(n) => {
                    withdraws_count += n.addrs.len();
                    self.handle_withdraws(sessionid,&n.addrs);
                }
                _ => {}
            }
        }
        self.cnt_updates += updates_count as u64;
        self.cnt_withdraws += withdraws_count as u64;
        Ok(())
    }
    pub fn needs_purge(&self) -> bool {
        if self.purge_after_withdraws > 0 {
            if self.cnt_withdraws / self.purge_after_withdraws != self.cnt_purge {
                return true;
            }
        }
        (chrono::Local::now() - self.purged) > self.purge_every
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
            let _rs = teststore.get(Rc::new(12));
            assert_eq!(teststore.len(), 1);
            teststore.purge();
            assert_eq!(teststore.len(), 1);
        }
        teststore.purge();
        assert_eq!(teststore.len(), 0);
    }
}
