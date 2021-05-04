use chrono::prelude::*;
use std::rc::Rc;
use zettabgp::prelude::*;

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
    pub items: std::collections::HashSet<RibItem<T>>,
}
impl<T: std::hash::Hash + Eq + PartialOrd + Ord> RibItemStore<T> {
    pub fn new() -> RibItemStore<T> {
        RibItemStore {
            items: std::collections::HashSet::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn purge(&mut self) {
        let mut trg = std::collections::HashSet::<RibItem<T>>::new();
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
pub trait BgpRIBKey: std::hash::Hash + std::cmp::Eq + std::cmp::Ord {
    fn getlabels(&self) -> Option<MplsLabels> {
        None
    }
}
impl<T: BgpItem<T> + std::hash::Hash + std::cmp::Eq + std::cmp::Ord> BgpRIBKey for Labeled<T> {
    fn getlabels(&self) -> Option<MplsLabels> {
        Some(self.labels.clone())
    }
}
impl<T: BgpItem<T> + std::hash::Hash + std::cmp::Eq + std::cmp::Ord> BgpRIBKey for WithRd<T> {}
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
pub struct BgpAttrHistory {
    pub items: std::collections::BTreeMap<DateTime<Local>, BgpAttrEntry>,
}
impl BgpAttrHistory {
    pub fn new() -> BgpAttrHistory {
        BgpAttrHistory {
            items: std::collections::BTreeMap::new(),
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
    pub fn get_last_entry<'a>(&'a self) -> Option<(&'a DateTime<Local>, &'a BgpAttrEntry)> {
        self.items.iter().last()
    }
}
pub struct BgpRIBSafi<T: BgpRIBKey> {
    pub log_size: usize,
    pub items: std::collections::BTreeMap<T, BgpAttrHistory>,
}
impl<T: BgpRIBKey> BgpRIBSafi<T> {
    pub fn new(logsize: usize) -> BgpRIBSafi<T> {
        BgpRIBSafi {
            log_size: logsize,
            items: std::collections::BTreeMap::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn handle_withdraws_afi(&mut self, v: &Vec<T>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
            match self.items.get_mut(&i) {
                None => {}
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    let attrs = match hist.get_last_entry() {
                        None => {
                            panic!("Empty history map")
                        }
                        Some(v) => v.1.attrs.clone(),
                    };
                    hist.items
                        .insert(now, BgpAttrEntry::new(false, attrs, i.getlabels()));
                }
            }
        }
    }
    pub fn handle_updates_afi(&mut self, v: Vec<T>, rattr: Rc<BgpAttrs>) {
        if v.len() < 1 {
            return;
        }
        let now = Local::now();
        for i in v.into_iter() {
            let histrec = BgpAttrEntry::new(true, rattr.clone(), i.getlabels());
            match self.items.get_mut(&i) {
                None => {
                    let mut hist = BgpAttrHistory::new();
                    hist.items.insert(now, histrec);
                    self.items.insert(i, hist);
                }
                Some(hist) => {
                    hist.shrink_hist(self.log_size - 1);
                    match hist.get_last_entry() {
                        None => {
                            panic!("Empty history map")
                        }
                        Some(_) => {
                            hist.items.insert(now, histrec);
                        }
                    }
                }
            }
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
    purge_attrs: u64,
}
unsafe impl Sync for BgpRIB {}
unsafe impl Send for BgpRIB {}

impl BgpRIB {
    pub fn new(logsize: usize, purge_after_withdraws: u64) -> BgpRIB {
        BgpRIB {
            pathes: RibItemStore::new(),
            comms: RibItemStore::new(),
            lcomms: RibItemStore::new(),
            extcomms: RibItemStore::new(),
            clusters: RibItemStore::new(),
            pmsi_ta_s: RibItemStore::new(),
            attrs: RibItemStore::new(),
            ipv4u: BgpRIBSafi::new(logsize),
            ipv4m: BgpRIBSafi::new(logsize),
            ipv4lu: BgpRIBSafi::new(logsize),
            vpnv4u: BgpRIBSafi::new(logsize),
            vpnv4m: BgpRIBSafi::new(logsize),
            ipv6u: BgpRIBSafi::new(logsize),
            ipv6lu: BgpRIBSafi::new(logsize),
            vpnv6u: BgpRIBSafi::new(logsize),
            vpnv6m: BgpRIBSafi::new(logsize),
            l2vpls: BgpRIBSafi::new(logsize),
            mvpn: BgpRIBSafi::new(logsize),
            evpn: BgpRIBSafi::new(logsize),
            fs4u: BgpRIBSafi::new(logsize),
            cnt_updates: 0,
            cnt_withdraws: 0,
            cnt_purge: 0,
            purge_attrs: purge_after_withdraws,
        }
    }
    pub fn purge(&mut self) {
        self.attrs.purge();
        self.clusters.purge();
        self.extcomms.purge();
        self.lcomms.purge();
        self.comms.purge();
        self.pathes.purge();
    }
    pub fn handle_withdraws(&mut self, withdraws: &BgpAddrs) {
        match withdraws {
            BgpAddrs::IPV4U(v) => self.ipv4u.handle_withdraws_afi(v),
            BgpAddrs::IPV4M(v) => self.ipv4m.handle_withdraws_afi(v),
            BgpAddrs::IPV4LU(v) => self.ipv4lu.handle_withdraws_afi(v),
            BgpAddrs::VPNV4U(v) => self.vpnv4u.handle_withdraws_afi(v),
            BgpAddrs::VPNV4M(v) => self.vpnv4m.handle_withdraws_afi(v),
            BgpAddrs::IPV6U(v) => self.ipv6u.handle_withdraws_afi(v),
            BgpAddrs::IPV6LU(v) => self.ipv6lu.handle_withdraws_afi(v),
            BgpAddrs::VPNV6U(v) => self.vpnv6u.handle_withdraws_afi(v),
            BgpAddrs::VPNV6M(v) => self.vpnv6m.handle_withdraws_afi(v),
            BgpAddrs::L2VPLS(v) => self.l2vpls.handle_withdraws_afi(v),
            BgpAddrs::MVPN(v) => self.mvpn.handle_withdraws_afi(v),
            BgpAddrs::EVPN(v) => self.evpn.handle_withdraws_afi(v),
            BgpAddrs::FS4U(v) => self.fs4u.handle_withdraws_afi(v),
            _ => {}
        };
    }
    pub fn handle_updates(&mut self, rattr: Rc<BgpAttrs>, updates: BgpAddrs) {
        match updates {
            BgpAddrs::IPV4U(v) => self.ipv4u.handle_updates_afi(v, rattr),
            BgpAddrs::IPV4M(v) => self.ipv4m.handle_updates_afi(v, rattr),
            BgpAddrs::IPV4LU(v) => self.ipv4lu.handle_updates_afi(v, rattr),
            BgpAddrs::VPNV4U(v) => self.vpnv4u.handle_updates_afi(v, rattr),
            BgpAddrs::VPNV4M(v) => self.vpnv4m.handle_updates_afi(v, rattr),
            BgpAddrs::IPV6U(v) => self.ipv6u.handle_updates_afi(v, rattr),
            BgpAddrs::IPV6LU(v) => self.ipv6lu.handle_updates_afi(v, rattr),
            BgpAddrs::VPNV6U(v) => self.vpnv6u.handle_updates_afi(v, rattr),
            BgpAddrs::VPNV6M(v) => self.vpnv6m.handle_updates_afi(v, rattr),
            BgpAddrs::L2VPLS(v) => self.l2vpls.handle_updates_afi(v, rattr),
            BgpAddrs::MVPN(v) => self.mvpn.handle_updates_afi(v, rattr),
            BgpAddrs::EVPN(v) => self.evpn.handle_updates_afi(v, rattr),
            BgpAddrs::FS4U(v) => self.fs4u.handle_updates_afi(v, rattr),
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
        self.handle_withdraws(&upd.withdraws);
        self.handle_updates(rattr.clone(), upd.updates);
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
                    self.handle_updates(cattr.clone(), n.addrs);
                }
                BgpAttrItem::MPWithdraws(n) => {
                    withdraws_count += n.addrs.len();
                    self.handle_withdraws(&n.addrs);
                }
                _ => {}
            }
        }
        self.cnt_updates += updates_count as u64;
        self.cnt_withdraws += withdraws_count as u64;
        if self.cnt_withdraws / self.purge_attrs != self.cnt_purge {
            self.cnt_purge = self.cnt_withdraws / self.purge_attrs;
            self.purge();
        }
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
            let _rs = teststore.get(Rc::new(12));
            assert_eq!(teststore.len(), 1);
            teststore.purge();
            assert_eq!(teststore.len(), 1);
        }
        teststore.purge();
        assert_eq!(teststore.len(), 0);
    }
}
