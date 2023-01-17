use crate::bgpattrs::BgpAttrs;
use crate::bgprib::{BgpRIBKey, BgpRIBSafi, BgpSessionEntry, ClonableIterator};
use crate::clone_iter;
use crate::service::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::sync::Arc;
use zettabgp::prelude::*;

pub struct SortIter<T> {
    sorted: Vec<T>,
}
impl<T> SortIter<T> {
    pub fn new(
        srciter: &mut (dyn std::iter::Iterator<Item = T>),
        fnc: &dyn Fn(&T, &T) -> std::cmp::Ordering,
    ) -> SortIter<T> {
        let mut v = Vec::<T>::new();
        srciter.for_each(|q| {
            v.push(q);
        });
        v.sort_by(|a, b| (fnc)(a, b));
        SortIter { sorted: v }
    }
}

impl<T> std::iter::Iterator for SortIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.sorted.pop()
    }
}

#[derive(Debug, PartialEq)]
pub enum FilterItemMatchResult {
    Unknown,
    No,
    Yes,
}
impl FilterItemMatchResult {
    /*
    pub fn not(&self) -> FilterItemMatchResult {
        match self {
            FilterItemMatchResult::Unknown => FilterItemMatchResult::Unknown,
            FilterItemMatchResult::No => FilterItemMatchResult::Yes,
            FilterItemMatchResult::Yes => FilterItemMatchResult::No,
        }
    }
    */
    pub fn soft(b: bool) -> FilterItemMatchResult {
        if b {
            FilterItemMatchResult::Yes
        } else {
            FilterItemMatchResult::Unknown
        }
    }
    pub fn multi(v: &[FilterItemMatchResult]) -> FilterItemMatchResult {
        let cy = v.iter().fold(0usize, |acc, x| {
            if *x == FilterItemMatchResult::Yes {
                acc + 1
            } else {
                acc
            }
        });
        let cn = v.iter().fold(0usize, |acc, x| {
            if *x == FilterItemMatchResult::No {
                acc + 1
            } else {
                acc
            }
        });
        if cy > cn {
            return FilterItemMatchResult::Yes;
        }
        if cn > cy {
            return FilterItemMatchResult::No;
        }
        FilterItemMatchResult::Unknown
    }
}
impl std::fmt::Display for FilterItemMatchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FilterItemMatchResult::Yes => f.write_str("Yes"),
            FilterItemMatchResult::No => f.write_str("No"),
            FilterItemMatchResult::Unknown => f.write_str("Unknown"),
        }
    }
}
impl std::ops::Not for FilterItemMatchResult {
    type Output = Self;
    fn not(self) -> Self::Output {
        match self {
            FilterItemMatchResult::Unknown => FilterItemMatchResult::Unknown,
            FilterItemMatchResult::No => FilterItemMatchResult::Yes,
            FilterItemMatchResult::Yes => FilterItemMatchResult::No,
        }
    }
}
impl From<bool> for FilterItemMatchResult {
    fn from(vl: bool) -> Self {
        if vl {
            FilterItemMatchResult::Yes
        } else {
            FilterItemMatchResult::No
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FilterASPath {
    Empty,
    Contains(BgpASpath),
    StartsWith(BgpASpath),
    EndsWith(BgpASpath),
    FullMatch(BgpASpath),
}
pub struct FilterRegex {
    pub restr: std::string::String,
    pub re: Regex,
}
impl FilterRegex {
    pub fn new(re_str: &str) -> Result<FilterRegex, regex::Error> {
        Ok(FilterRegex {
            restr: std::string::String::from(re_str),
            re: match Regex::new(re_str) {
                Ok(r) => r,
                Err(e) => return Err(e),
            },
        })
    }
}
impl std::fmt::Debug for FilterRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterRegex")
            .field("restr", &self.restr)
            .finish()
    }
}
impl PartialEq for FilterRegex {
    fn eq(&self, other: &Self) -> bool {
        self.restr == other.restr
    }
}
#[derive(Debug, PartialEq)]
pub enum FilterExtComm {
    Num(u32),
    PairNum((u32, u32)),
    IPv4(BgpAddrV4),
    PairNumIP((BgpAddrV4, u32)),
}

#[derive(Debug, PartialEq)]
pub enum FilterItemKind {
    Attr,
    Net,
    Host,
}
#[derive(Debug, PartialEq)]
pub enum FilterItem {
    None,
    V4(BgpAddrV4),
    V6(BgpAddrV6),
    NHV4(BgpAddrV4),
    NHV6(BgpAddrV6),
    MCV4(BgpAddrV4),
    MCV6(BgpAddrV6),
    RD(BgpRD),
    ASPath(FilterASPath),
    Community(BgpCommunity),
    Num(u64),
    Regexp(FilterRegex),
    ExtCommunity(FilterExtComm),
}
impl FilterItem {
    pub fn kind(&self) -> FilterItemKind {
        match self {
            FilterItem::None => FilterItemKind::Attr,
            FilterItem::V4(n) => {
                if n.prefixlen < 32 {
                    FilterItemKind::Net
                } else {
                    FilterItemKind::Host
                }
            }
            FilterItem::V6(n) => {
                if n.prefixlen < 128 {
                    FilterItemKind::Net
                } else {
                    FilterItemKind::Host
                }
            }
            _ => FilterItemKind::Attr,
        }
    }
}
pub trait FilterMatchRoute:
    std::cmp::Eq + std::hash::Hash + std::fmt::Display + std::marker::Sized
{
    fn match_item(&self, _fi: &FilterItem) -> FilterItemMatchResult {
        FilterItemMatchResult::Unknown
    }
    fn match_super_item(&self, _fi: &FilterItem) -> FilterItemMatchResult {
        FilterItemMatchResult::Unknown
    }
    fn len(&self) -> usize {
        0
    }
    fn get_subnet_range(_fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        None
    }
    fn get_supernet_range(_fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        None
    }
}
impl FilterMatchRoute for std::net::IpAddr {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_sockaddr(self)
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_sockaddr(self)
    }
    fn len(&self) -> usize {
        match self {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        }
    }
    fn get_subnet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V4(ref n) => {
                Some(std::net::IpAddr::V4(n.range_first())..=std::net::IpAddr::V4(n.range_last()))
            }
            _ => None,
        }
    }
    fn get_supernet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V4(ref n) => Some(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
                    ..=std::net::IpAddr::V4(n.range_last()),
            ),
            _ => None,
        }
    }
}

impl FilterMatchRoute for BgpAddrV4 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_ipv4(&self)
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_super_ipv4(&self)
    }
    fn len(&self) -> usize {
        self.prefixlen as usize
    }
    fn get_subnet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V4(ref n) => Some(
                BgpAddrV4::new(n.range_first(), n.prefixlen)..=BgpAddrV4::new(n.range_last(), 32),
            ),
            _ => None,
        }
    }
    fn get_supernet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V4(ref n) => Some(
                BgpAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0)
                    ..=BgpAddrV4::new(n.range_last(), 32),
            ),
            _ => None,
        }
    }
}
impl FilterMatchRoute for BgpAddrV6 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_ipv6(&self)
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_super_ipv6(&self)
    }
    fn len(&self) -> usize {
        self.prefixlen as usize
    }
    fn get_subnet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V6(ref n) => Some(
                BgpAddrV6::new(n.range_first(), n.prefixlen)..=BgpAddrV6::new(n.range_last(), 128),
            ),
            _ => None,
        }
    }
    fn get_supernet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match fi {
            FilterItem::V6(ref n) => Some(
                BgpAddrV6::new(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)
                    ..=BgpAddrV6::new(n.range_last(), 128),
            ),
            _ => None,
        }
    }
}
impl FilterMatchRoute for BgpAddrL2 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi {
            FilterItem::RD(_) => fi.match_rd(&self.rd),
            FilterItem::Num(n) => (((self.site as u64) == *n)
                || ((self.offset as u64) <= *n && (self.range as u64) >= *n))
                .into(),
            FilterItem::Regexp(fp) => {
                FilterItemMatchResult::soft(fp.re.is_match(self.to_string().as_str()))
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
}
impl FilterMatchRoute for BgpMVPN1 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => self.originator.match_item(&fi),
            n => n,
        }
    }
}
impl FilterMatchRoute for BgpMVPN2 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_rd(&self.rd)
    }
}
impl FilterMatchRoute for BgpMVPN3 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        let m1 = self.originator.match_item(&fi);
        let m2 = self.source.match_item(&fi);
        let m3 = self.group.match_item(&fi);
        FilterItemMatchResult::multi(&[m1, m2, m3])
    }
}
impl FilterMatchRoute for BgpMVPN4 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match self.spmsi.match_item(fi) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        self.originator.match_item(&fi)
    }
}
impl FilterMatchRoute for BgpMVPN5 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        let m1 = self.source.match_item(&fi);
        let m2 = self.group.match_item(&fi);
        FilterItemMatchResult::multi(&[m1, m2])
    }
}
impl FilterMatchRoute for BgpMVPN67 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        let m1 = self.rp.match_item(&fi);
        let m2 = self.group.match_item(&fi);
        FilterItemMatchResult::multi(&[m1, m2])
    }
}
impl FilterMatchRoute for BgpMVPN {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match self {
            BgpMVPN::T1(r) => r.match_item(fi),
            BgpMVPN::T2(r) => r.match_item(fi),
            BgpMVPN::T3(r) => r.match_item(fi),
            BgpMVPN::T4(r) => r.match_item(fi),
            BgpMVPN::T5(r) => r.match_item(fi),
            BgpMVPN::T6(r) => r.match_item(fi),
            BgpMVPN::T7(r) => r.match_item(fi),
        }
    }
}
impl FilterMatchRoute for BgpEVPN1 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        fi.match_rd(&self.rd)
    }
}
impl FilterMatchRoute for BgpEVPN2 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        if let Some(ip) = self.ip {
            return ip.match_item(&fi);
        }
        FilterItemMatchResult::Unknown
    }
}
impl FilterMatchRoute for BgpEVPN3 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        self.ip.match_item(&fi)
    }
}
impl FilterMatchRoute for BgpEVPN4 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => {}
            n => return n,
        };
        self.ip.match_item(&fi)
    }
}
impl FilterMatchRoute for BgpEVPN {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match self {
            BgpEVPN::EVPN1(r) => r.match_item(fi),
            BgpEVPN::EVPN2(r) => r.match_item(fi),
            BgpEVPN::EVPN3(r) => r.match_item(fi),
            BgpEVPN::EVPN4(r) => r.match_item(fi),
        }
    }
}
impl FilterMatchRoute for BgpMdtV4 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        FilterItemMatchResult::multi(&[self.addr.match_item(&fi), fi.match_addr_v4(&self.group)])
    }
}
impl FilterMatchRoute for BgpMdtV6 {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        FilterItemMatchResult::multi(&[self.addr.match_item(&fi), fi.match_addr_v6(&self.group)])
    }
}
impl FilterMatchRoute for BgpFlowSpec<BgpAddrV4> {}
impl<T: BgpItem<T> + FilterMatchRoute + Clone> FilterMatchRoute for WithRd<T> {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        //eprintln!("WithRd::match_item {:?} - {}", fi, self);
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => self.prefix.match_item(&fi),
            n => n,
        }
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi.match_rd(&self.rd) {
            FilterItemMatchResult::Unknown => self.prefix.match_super_item(&fi),
            n => n,
        }
    }
    fn len(&self) -> usize {
        64 + self.prefix.len()
    }
    fn get_subnet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match T::get_subnet_range(fi) {
            None => None,
            Some(r) => Some(
                Self::new(BgpRD::new(0, 0), (*(r.start())).clone())
                    ..=Self::new(BgpRD::new(0xffffffff, 0xffffffff), (*(r.end())).clone()),
            ),
        }
    }
    fn get_supernet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match T::get_supernet_range(fi) {
            None => None,
            Some(r) => Some(
                Self::new(BgpRD::new(0, 0), (*(r.start())).clone())
                    ..=Self::new(BgpRD::new(0xffffffff, 0xffffffff), (*(r.end())).clone()),
            ),
        }
    }
}
impl<T: BgpItem<T> + FilterMatchRoute + Clone> FilterMatchRoute for Labeled<T> {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        self.prefix.match_item(&fi)
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        self.prefix.match_super_item(&fi)
    }
    fn len(&self) -> usize {
        self.labels.labels.len() * 24 + self.prefix.len()
    }
    fn get_subnet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match T::get_subnet_range(fi) {
            None => None,
            Some(r) => {
                Some(Self::new_nl((*(r.start())).clone())..=Self::new_nl((*(r.end())).clone()))
            }
        }
    }
    fn get_supernet_range(fi: &FilterItem) -> Option<RangeInclusive<Self>> {
        match T::get_supernet_range(fi) {
            None => None,
            Some(r) => {
                Some(Self::new_nl((*(r.start())).clone())..=Self::new_nl((*(r.end())).clone()))
            }
        }
    }
}
impl FilterMatchRoute for BgpExtCommunity {
    fn match_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        match fi {
            FilterItem::ExtCommunity(excf) => match excf {
                FilterExtComm::Num(n) => FilterItemMatchResult::soft(
                    (self.a as u32) == *n || self.b == *n || ((self.b >> 16) & 0xffff) == *n,
                ),
                FilterExtComm::PairNum(n) => {
                    FilterItemMatchResult::soft((self.a as u32) == n.0 && self.b == n.1)
                }
                FilterExtComm::IPv4(bav4) => FilterItemMatchResult::soft(
                    self.ctype == 1
                        && bav4.in_subnet(&std::net::Ipv4Addr::new(
                            ((self.a >> 8) & 0xff) as u8,
                            (self.a & 0xff) as u8,
                            ((self.b >> 24) & 0xff) as u8,
                            ((self.b >> 16) & 0xff) as u8,
                        )),
                ),
                FilterExtComm::PairNumIP((bav4, n)) => FilterItemMatchResult::soft(
                    self.ctype == 1
                        && (self.b & 0xffff) == *n
                        && bav4.in_subnet(&std::net::Ipv4Addr::new(
                            ((self.a >> 8) & 0xff) as u8,
                            (self.a & 0xff) as u8,
                            ((self.b >> 24) & 0xff) as u8,
                            ((self.b >> 16) & 0xff) as u8,
                        )),
                ),
            },
            _ => FilterItemMatchResult::Unknown,
        }
    }
    fn match_super_item(&self, fi: &FilterItem) -> FilterItemMatchResult {
        self.match_item(fi)
    }
}
#[derive(Debug)]
pub struct FilterTerm {
    pub item: FilterItem,
    pub predicate: FilterItemMatchResult,
}
pub struct RouteFilter {
    pub terms: std::vec::Vec<FilterTerm>,
}
#[derive(Clone)]
pub struct RouteFilterParams<'a> {
    pub filter: &'a RouteFilter,
    pub maxdepth: usize,
    pub onlyactive: bool,
}
impl<'a> RouteFilterParams<'a> {
    pub fn new(filter: &'a RouteFilter, maxdepth: usize, onlyactive: bool) -> RouteFilterParams {
        RouteFilterParams {
            filter,
            maxdepth,
            onlyactive,
        }
    }
}
pub struct RouteFilterSubnets<'a, 'b, T: FilterMatchRoute + BgpRIBKey> {
    filter: RouteFilterParams<'a>,
    srcitr: ClonableIterator<'b, &'b T, &'b BgpSessionEntry>,
}
impl<'a, 'b, T: FilterMatchRoute + BgpRIBKey> RouteFilterSubnets<'a, 'b, T> {
    pub fn new(
        filter: &'a RouteFilter,
        maxdepth: usize,
        onlyactive: bool,
        srcafi: &'b BgpRIBSafi<T>,
    ) -> RouteFilterSubnets<'a, 'b, T> {
        Self {
            filter: RouteFilterParams::new(filter, maxdepth, onlyactive),
            srcitr: match filter.find_least_subnet() {
                None => srcafi.get_iter(filter),
                Some(fnet) => match fnet.get_subnet_range::<T>() {
                    None => clone_iter!(srcafi.items.iter()),
                    Some(rng) => clone_iter!(srcafi.items.range(rng)),
                },
            },
        }
    }
}
impl<'a, 'b, T: FilterMatchRoute + BgpRIBKey> std::iter::Iterator
    for RouteFilterSubnets<'a, 'b, T>
{
    type Item = (&'b T, &'b BgpSessionEntry);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.srcitr.next() {
                None => break,
                Some(q) => {
                    if q.1
                        .items
                        .iter()
                        .find(|ssitr| {
                            ssitr
                                .1
                                .items
                                .iter()
                                .find(|pitr| {
                                    pitr.1
                                        .items
                                        .iter()
                                        .filter(|hr| {
                                            if self.filter.onlyactive {
                                                hr.1.active
                                            } else {
                                                true
                                            }
                                        })
                                        .skip(if pitr.1.items.len() > self.filter.maxdepth {
                                            pitr.1.items.len() - self.filter.maxdepth
                                        } else {
                                            0
                                        })
                                        .find(|histitem| {
                                            self.filter.filter.match_route(q.0, &histitem.1.attrs)
                                                == FilterItemMatchResult::Yes
                                        })
                                        .is_some()
                                })
                                .is_some()
                        })
                        .is_some()
                    {
                        return Some(q);
                    }
                }
            }
        }
        None
    }
}
pub struct RouteFilterSupernets<'a, 'b, T: FilterMatchRoute + BgpRIBKey> {
    filter: RouteFilterParams<'a>,
    srcitr: ClonableIterator<'b, &'b T, &'b BgpSessionEntry>,
}
impl<'a, 'b, T: FilterMatchRoute + BgpRIBKey> RouteFilterSupernets<'a, 'b, T> {
    pub fn new(
        filter: &'a RouteFilter,
        maxdepth: usize,
        onlyactive: bool,
        srcafi: &'b BgpRIBSafi<T>,
    ) -> RouteFilterSupernets<'a, 'b, T> {
        RouteFilterSupernets {
            filter: RouteFilterParams::new(filter,maxdepth,onlyactive),
            srcitr: //srcafi.items.iter(),
            match filter.find_least_subnet() {
                None => srcafi.get_iter(filter),
                Some(fnet) => {
                    match fnet.get_supernet_range::<T>() {
                        None => clone_iter!(srcafi.items.iter()),
                        Some(rng) => clone_iter!(srcafi.items.range(rng)),
                    }
                }
            },
        }
    }
}
impl<'a, 'b, T: FilterMatchRoute + BgpRIBKey> std::iter::Iterator
    for RouteFilterSupernets<'a, 'b, T>
{
    type Item = (&'b T, &'b BgpSessionEntry);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.srcitr.next() {
                None => break,
                Some(q) => {
                    if q.1
                        .items
                        .iter()
                        .find(|ssitr| {
                            ssitr
                                .1
                                .items
                                .iter()
                                .find(|pitr| {
                                    pitr.1
                                        .items
                                        .iter()
                                        .filter(|hr| {
                                            if self.filter.onlyactive {
                                                hr.1.active
                                            } else {
                                                true
                                            }
                                        })
                                        .skip(if pitr.1.items.len() > self.filter.maxdepth {
                                            pitr.1.items.len() - self.filter.maxdepth
                                        } else {
                                            0
                                        })
                                        .find(|histitem| {
                                            self.filter
                                                .filter
                                                .match_super_route(q.0, &histitem.1.attrs)
                                                == FilterItemMatchResult::Yes
                                        })
                                        .is_some()
                                })
                                .is_some()
                        })
                        .is_some()
                    {
                        return Some(q);
                    }
                }
            }
        }
        None
    }
}

impl RouteFilter {
    pub fn new() -> RouteFilter {
        RouteFilter { terms: Vec::new() }
    }
    pub fn parse(&mut self, st: &str) {
        for s in st.split(' ') {
            match FilterTerm::parse(s) {
                Some(t) => self.terms.push(t),
                None => {}
            }
        }
    }
    pub fn fromstr(st: &str) -> RouteFilter {
        let mut ret = Self::new();
        ret.parse(st);
        ret
    }
    pub fn iter_nets<'a, T: FilterMatchRoute + BgpRIBKey>(
        &'a self,
        safi: &'a BgpRIBSafi<T>,
        takemaxdepth: usize,
        takeonlyactive: bool,
    ) -> RouteFilterSubnets<'a, 'a, T> {
        RouteFilterSubnets::new(&self, takemaxdepth, takeonlyactive, safi)
    }
    pub fn iter_super_nets<'a, T: FilterMatchRoute + BgpRIBKey>(
        &'a self,
        safi: &'a BgpRIBSafi<T>,
        takemaxdepth: usize,
        takeonlyactive: bool,
    ) -> RouteFilterSupernets<'a, 'a, T> {
        RouteFilterSupernets::new(&self, takemaxdepth, takeonlyactive, safi)
    }
    pub fn find_best_supernet<'a, T: FilterMatchRoute + BgpRIBKey>(
        &'a self,
        safi: &'a BgpRIBSafi<T>,
        takemaxdepth: usize,
        takeonlyactive: bool,
    ) -> Option<(&'a T, &'a BgpSessionEntry)> {
        let mut ret: Option<(&'a T, &'a BgpSessionEntry)> = None;
        for q in RouteFilterSupernets::new(&self, takemaxdepth, takeonlyactive, safi) {
            match ret {
                None => {
                    ret = Some(q);
                }
                Some(ref x) => {
                    if x.0.len() < q.0.len() {
                        ret = Some(q);
                    }
                }
            }
        }
        return ret;
    }
    pub fn match_attr(&self, attr: &BgpAttrs) -> FilterItemMatchResult {
        if self.terms.len() < 1 {
            return FilterItemMatchResult::Yes;
        }
        let mut cnt: usize = 0;
        for i in self.terms.iter() {
            if i.item.kind() == FilterItemKind::Attr {
                match i.match_attr(attr) {
                    FilterItemMatchResult::Unknown => {}
                    n => {
                        return n;
                    }
                };
                cnt += 1;
            }
        }
        if cnt < 1 {
            return FilterItemMatchResult::Yes;
        }
        FilterItemMatchResult::Unknown
    }
    pub fn match_route<T: FilterMatchRoute>(
        &self,
        route: &T,
        attr: &BgpAttrs,
    ) -> FilterItemMatchResult {
        if self.terms.len() < 1 {
            return FilterItemMatchResult::Yes;
        }
        let mut result_route = FilterItemMatchResult::Yes;
        let mut result_attr = FilterItemMatchResult::Yes;
        for i in self.terms.iter() {
            if i.item.kind() == FilterItemKind::Attr {
                match i.match_route(route, attr) {
                    FilterItemMatchResult::Unknown => result_attr = FilterItemMatchResult::Unknown,
                    FilterItemMatchResult::No => {
                        return FilterItemMatchResult::No;
                    }
                    FilterItemMatchResult::Yes => {}
                }
            } else {
                match i.match_route(route, attr) {
                    FilterItemMatchResult::Unknown => result_route = FilterItemMatchResult::Unknown,
                    FilterItemMatchResult::No => {
                        return FilterItemMatchResult::No;
                    }
                    FilterItemMatchResult::Yes => {}
                }
            }
        }
        if result_route == FilterItemMatchResult::Yes && result_attr == FilterItemMatchResult::Yes {
            FilterItemMatchResult::Yes
        } else {
            FilterItemMatchResult::Unknown
        }
    }
    pub fn match_super_route<T: FilterMatchRoute>(
        &self,
        route: &T,
        attr: &BgpAttrs,
    ) -> FilterItemMatchResult {
        if self.terms.len() < 1 {
            return FilterItemMatchResult::Yes;
        }
        let mut result_route = FilterItemMatchResult::Yes;
        let mut result_attr = FilterItemMatchResult::Yes;
        for i in self.terms.iter() {
            if i.item.kind() == FilterItemKind::Attr {
                match i.match_super_route(route, attr) {
                    FilterItemMatchResult::Unknown => result_attr = FilterItemMatchResult::Unknown,
                    FilterItemMatchResult::No => {
                        return FilterItemMatchResult::No;
                    }
                    FilterItemMatchResult::Yes => {}
                }
            } else {
                match i.match_super_route(route, attr) {
                    FilterItemMatchResult::Unknown => result_route = FilterItemMatchResult::Unknown,
                    FilterItemMatchResult::No => {
                        return FilterItemMatchResult::No;
                    }
                    FilterItemMatchResult::Yes => {}
                }
            }
        }
        if result_route == FilterItemMatchResult::Yes && result_attr == FilterItemMatchResult::Yes {
            FilterItemMatchResult::Yes
        } else {
            FilterItemMatchResult::Unknown
        }
    }
    fn find_least_subnet<'a>(&'a self) -> Option<&'a FilterItem> {
        let mut ret: Option<&'a FilterItem> = None;
        for i in self.terms.iter() {
            if i.predicate == FilterItemMatchResult::No {
                continue;
            };
            match i.item {
                FilterItem::V4(ref r) => match ret {
                    None => ret = Some(&i.item),
                    Some(lve) => match lve {
                        FilterItem::V4(lv) => {
                            if r.prefixlen > lv.prefixlen {
                                ret = Some(&i.item);
                            }
                        }
                        _ => {}
                    },
                },
                FilterItem::V6(ref r) => match ret {
                    None => ret = Some(&i.item),
                    Some(lve) => match lve {
                        FilterItem::V6(lv) => {
                            if r.prefixlen > lv.prefixlen {
                                ret = Some(&i.item);
                            }
                        }
                        _ => {
                            ret = Some(&i.item);
                        }
                    },
                },
                _ => {}
            }
        }
        ret
    }
    pub fn find_aspath_item<'a>(&'a self) -> BTreeSet<BgpAS> {
        let mut ret: BTreeSet<BgpAS> = BTreeSet::new();
        for i in self.terms.iter() {
            if i.predicate == FilterItemMatchResult::No {
                continue;
            };
            match &i.item {
                FilterItem::ASPath(asp) => match asp {
                    FilterASPath::Contains(p) => p.value.iter().for_each(|x| {
                        ret.insert(x.clone());
                    }),
                    FilterASPath::StartsWith(p) => p.value.iter().for_each(|x| {
                        ret.insert(x.clone());
                    }),
                    FilterASPath::EndsWith(p) => p.value.iter().for_each(|x| {
                        ret.insert(x.clone());
                    }),
                    FilterASPath::FullMatch(p) => p.value.iter().for_each(|x| {
                        ret.insert(x.clone());
                    }),
                    FilterASPath::Empty => {}
                },
                _ => {}
            }
        }
        ret
    }
    pub fn find_community_item<'a>(&'a self) -> BTreeSet<BgpCommunity> {
        let mut ret: BTreeSet<BgpCommunity> = BTreeSet::new();
        for i in self.terms.iter() {
            if i.predicate == FilterItemMatchResult::No {
                continue;
            };
            match &i.item {
                FilterItem::Community(x) => {
                    ret.insert(x.clone());
                }
                _ => {}
            }
        }
        ret
    }
    pub fn find_extcommunity_item<'a>(&'a self) -> BTreeSet<BgpExtCommunity> {
        let mut ret: BTreeSet<BgpExtCommunity> = BTreeSet::new();
        for i in self.terms.iter() {
            if i.predicate == FilterItemMatchResult::No {
                continue;
            };
            match &i.item {
                FilterItem::ExtCommunity(x) => {
                    match x {
                        FilterExtComm::PairNum(t) => {
                            ret.insert(BgpExtCommunity::rt_asn(t.0 as u16, t.1));
                        }
                        FilterExtComm::PairNumIP(t) => {
                            ret.insert(BgpExtCommunity::rt_ipn(t.0.addr, t.1 as u16));
                        }
                        _ => {}
                    };
                }
                _ => {}
            }
        }
        ret
    }
}

impl FilterItem {
    pub fn new() -> FilterItem {
        FilterItem::None
    }
    pub fn parse(itemstr: &str) -> FilterItem {
        lazy_static! {
            static ref RE_IPV4: Regex =
                Regex::new(r"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/([0-9]+))*$").unwrap();
            static ref RE_IPV6: Regex = Regex::new(r"^([0-9A-Fa-f:]+)(/([0-9]+))*$").unwrap();
            static ref RE_NHIPV4: Regex =
                Regex::new(r"^nh:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/([0-9]+))*$").unwrap();
            static ref RE_NHIPV6: Regex = Regex::new(r"^nh:([0-9A-Fa-f:]+)(/([0-9]+))*$").unwrap();
            static ref RE_RD: Regex = Regex::new(r"^rd:([0-9]+):([0-9]+)$").unwrap();
            static ref RE_RDIP: Regex =
                Regex::new(r"^rd:([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+):([0-9]+)$").unwrap();
            static ref RE_AS: Regex = Regex::new(r"^as:(\^*)([0-9,]+)*(\$)*$").unwrap();
            static ref RE_C: Regex = Regex::new(r"^c[^:]*:([0-9]+):([0-9]+)$").unwrap();
            static ref RE_NUM: Regex = Regex::new(r"^([0-9]+)$").unwrap();
            static ref RE_RE: Regex = Regex::new(r"^re:(.*)$").unwrap();
            static ref RE_RT_N: Regex = Regex::new(r"^(rt|target|ext-target):([0-9]+)$").unwrap();
            static ref RE_RT_P: Regex =
                Regex::new(r"^(rt|target|ext-target):([0-9]+):([0-9]+)$").unwrap();
            static ref RE_RT_IP: Regex =
                Regex::new(r"^(rt|target|ext-target):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$").unwrap();
            static ref RE_RT_IPN: Regex =
                Regex::new(r"^(rt|target|ext-target):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$")
                    .unwrap();
        }
        match RE_NUM.captures(itemstr) {
            Some(caps) => {
                match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => {
                            return FilterItem::Num(q);
                        }
                        Err(_) => {}
                    },
                    None => {}
                };
            }
            _ => {}
        };
        match RE_IPV4.captures(itemstr) {
            Some(caps) => {
                let addr = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => {
                            return FilterItem::None;
                        }
                    },
                    None => {
                        return FilterItem::None;
                    }
                };
                let pfx = match caps.get(3) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 32,
                    },
                    None => 32,
                };
                let adr = BgpAddrV4::new(addr, pfx);
                if adr.is_multicast() {
                    return FilterItem::MCV4(adr);
                } else {
                    return FilterItem::V4(adr);
                }
            }
            _ => {}
        };
        match RE_IPV6.captures(itemstr) {
            Some(caps) => {
                let addr = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => {
                            return FilterItem::None;
                        }
                    },
                    None => {
                        return FilterItem::None;
                    }
                };
                let pfx = match caps.get(3) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 128,
                    },
                    None => 128,
                };
                let adr = BgpAddrV6::new(addr, pfx);
                if adr.is_multicast() {
                    return FilterItem::MCV6(adr);
                } else {
                    return FilterItem::V6(adr);
                }
            }
            _ => {}
        };
        match RE_NHIPV4.captures(itemstr) {
            Some(caps) => {
                let addr = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => {
                            return FilterItem::None;
                        }
                    },
                    None => {
                        return FilterItem::None;
                    }
                };
                let pfx = match caps.get(3) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 32,
                    },
                    None => 32,
                };
                return FilterItem::NHV4(BgpAddrV4::new(addr, pfx));
            }
            _ => {}
        };
        match RE_NHIPV6.captures(itemstr) {
            Some(caps) => {
                let addr = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => {
                            return FilterItem::None;
                        }
                    },
                    None => {
                        return FilterItem::None;
                    }
                };
                let pfx = match caps.get(3) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 128,
                    },
                    None => 128,
                };
                return FilterItem::NHV6(BgpAddrV6::new(addr, pfx));
            }
            _ => {}
        };
        match RE_RD.captures(itemstr) {
            Some(caps) => {
                let rdh = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                let rdl = match caps.get(2) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                return FilterItem::RD(BgpRD::new(rdh, rdl));
            }
            _ => {}
        };
        match RE_RDIP.captures(itemstr) {
            Some(caps) => {
                let mut vls: Vec<u32> = Vec::new();
                for i in 1..7 {
                    vls.push(match caps.get(i) {
                        Some(n) => match n.as_str().parse() {
                            Ok(q) => q,
                            Err(_) => break,
                        },
                        None => break,
                    })
                }
                if vls.len() == 5 {
                    return FilterItem::RD(BgpRD::new(
                        0x10000 | (vls[0] << 8) | vls[1],
                        (vls[2] << 24) | (vls[3] << 16) | (vls[4] & 0xffff),
                    ));
                }
            }
            _ => {}
        };
        match RE_AS.captures(itemstr) {
            Some(caps) => {
                let sa = BgpASpath::from(match caps.get(2) {
                    Some(sv) => {
                        let mut v: Vec<u32> = Vec::new();
                        for s in sv.as_str().split(',') {
                            match s.parse() {
                                Ok(n) => v.push(n),
                                Err(_) => {}
                            }
                        }
                        v
                    }
                    None => Vec::<u32>::new(),
                });
                if sa.value.len() < 1 {
                    return FilterItem::ASPath(FilterASPath::Empty);
                }
                let sb = match caps.get(1) {
                    Some(s) => s.as_str(),
                    None => "",
                };
                let se = match caps.get(3) {
                    Some(s) => s.as_str(),
                    None => "",
                };
                return FilterItem::ASPath(if sb == "^" && se == "$" {
                    FilterASPath::FullMatch(sa)
                } else if se == "$" {
                    FilterASPath::EndsWith(sa)
                } else if sb == "^" {
                    FilterASPath::StartsWith(sa)
                } else {
                    FilterASPath::Contains(sa)
                });
            }
            _ => {}
        };
        match RE_C.captures(itemstr) {
            Some(caps) => {
                let ch = match caps.get(1) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                let cl = match caps.get(2) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                return FilterItem::Community(BgpCommunity::from(ch, cl));
            }
            _ => {}
        };
        match RE_RE.captures(itemstr) {
            Some(caps) => {
                match caps.get(1) {
                    Some(s) => match FilterRegex::new(s.as_str()) {
                        Ok(f) => {
                            return FilterItem::Regexp(f);
                        }
                        Err(_) => {}
                    },
                    None => {}
                };
            }
            _ => {}
        };
        match RE_RT_N.captures(itemstr) {
            Some(caps) => {
                match caps.get(2) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => return FilterItem::ExtCommunity(FilterExtComm::Num(q)),
                        Err(_) => {}
                    },
                    None => {}
                };
            }
            _ => {}
        };
        match RE_RT_P.captures(itemstr) {
            Some(caps) => {
                let ch = match caps.get(2) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                let cl = match caps.get(3) {
                    Some(n) => match n.as_str().parse() {
                        Ok(q) => q,
                        Err(_) => 0,
                    },
                    None => 0,
                };
                return FilterItem::ExtCommunity(FilterExtComm::PairNum((ch, cl)));
            }
            _ => {}
        };
        match RE_RT_IP.captures(itemstr) {
            Some(caps) => {
                match caps.get(2) {
                    Some(n) => match n.as_str().parse() {
                        Ok(addr) => {
                            return FilterItem::ExtCommunity(FilterExtComm::IPv4(BgpAddrV4::new(
                                addr, 32,
                            )));
                        }
                        Err(_) => {}
                    },
                    None => {}
                };
            }
            _ => {}
        };
        if let Some(caps) = RE_RT_IPN.captures(itemstr) {
            if let Some(n2) = caps.get(2) {
                if let Ok(addr) = n2.as_str().parse() {
                    if let Some(n3) = caps.get(3) {
                        if let Ok(num) = n3.as_str().parse() {
                            return FilterItem::ExtCommunity(FilterExtComm::PairNumIP((
                                BgpAddrV4::new(addr, 32),
                                num,
                            )));
                        };
                    };
                };
            };
        };
        warn!("Unknown filter item '{}'", itemstr);
        FilterItem::None
    }
    pub fn match_sockaddr(&self, addr: &std::net::IpAddr) -> FilterItemMatchResult {
        match self {
            FilterItem::V4(net) => match addr {
                std::net::IpAddr::V4(a) => {
                    if is_multicast(addr) {
                        FilterItemMatchResult::Unknown
                    } else {
                        net.in_subnet(a).into()
                    }
                }
                _ => FilterItemMatchResult::Unknown,
            },
            FilterItem::MCV4(net) => match addr {
                std::net::IpAddr::V4(a) => {
                    if is_multicast(addr) {
                        net.in_subnet(a).into()
                    } else {
                        FilterItemMatchResult::Unknown
                    }
                }
                _ => FilterItemMatchResult::Unknown,
            },
            FilterItem::V6(net) => match addr {
                std::net::IpAddr::V6(a) => {
                    if is_multicast(addr) {
                        FilterItemMatchResult::Unknown
                    } else {
                        net.in_subnet(a).into()
                    }
                }
                _ => FilterItemMatchResult::Unknown,
            },
            FilterItem::MCV6(net) => match addr {
                std::net::IpAddr::V6(a) => {
                    if is_multicast(addr) {
                        net.in_subnet(a).into()
                    } else {
                        FilterItemMatchResult::Unknown
                    }
                }
                _ => FilterItemMatchResult::Unknown,
            },
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_addr_v4(&self, addr: &std::net::Ipv4Addr) -> FilterItemMatchResult {
        match self {
            FilterItem::V4(net) => {
                if is_multicast_v4(addr) {
                    FilterItemMatchResult::Unknown
                } else {
                    net.in_subnet(addr).into()
                }
            }
            FilterItem::MCV4(net) => {
                if is_multicast_v4(addr) {
                    net.in_subnet(addr).into()
                } else {
                    FilterItemMatchResult::Unknown
                }
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_addr_v6(&self, addr: &std::net::Ipv6Addr) -> FilterItemMatchResult {
        match self {
            FilterItem::V6(net) => {
                if is_multicast_v6(addr) {
                    FilterItemMatchResult::Unknown
                } else {
                    net.in_subnet(addr).into()
                }
            }
            FilterItem::MCV6(net) => {
                if is_multicast_v6(addr) {
                    net.in_subnet(addr).into()
                } else {
                    FilterItemMatchResult::Unknown
                }
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_super_ipv4(&self, route: &BgpAddrV4) -> FilterItemMatchResult {
        match self {
            FilterItem::V4(net) => route.contains(net).into(),
            FilterItem::Num(n) => FilterItemMatchResult::soft(
                (route.prefixlen as u64) == *n || (route.prefixlen as u64) == *n,
            ),
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_super_ipv6(&self, route: &BgpAddrV6) -> FilterItemMatchResult {
        match self {
            FilterItem::V6(net) => route.contains(net).into(),
            FilterItem::Num(n) => FilterItemMatchResult::soft(
                (route.prefixlen as u64) == *n || (route.prefixlen as u64) == *n,
            ),
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_ipv4(&self, route: &BgpAddrV4) -> FilterItemMatchResult {
        match self {
            FilterItem::V4(net) => {
                if route.is_multicast() {
                    FilterItemMatchResult::Unknown
                } else {
                    net.contains(route).into()
                }
            }
            FilterItem::MCV4(net) => {
                if route.is_multicast() {
                    net.contains(route).into()
                } else {
                    FilterItemMatchResult::Unknown
                }
            }
            FilterItem::Num(n) => {
                ((route.prefixlen as u64) == *n || (route.prefixlen as u64) == *n).into()
            }
            FilterItem::Regexp(fp) => {
                FilterItemMatchResult::soft(fp.re.is_match(route.to_string().as_str()))
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_ipv6(&self, route: &BgpAddrV6) -> FilterItemMatchResult {
        match self {
            FilterItem::V6(net) => {
                if route.is_multicast() {
                    FilterItemMatchResult::Unknown
                } else {
                    net.contains(route).into()
                }
            }
            FilterItem::MCV6(net) => {
                if route.is_multicast() {
                    net.contains(route).into()
                } else {
                    FilterItemMatchResult::Unknown
                }
            }
            FilterItem::Num(n) => FilterItemMatchResult::soft(
                (route.prefixlen as u64) == *n || (route.prefixlen as u64) == *n,
            ),
            FilterItem::Regexp(fp) => {
                FilterItemMatchResult::soft(fp.re.is_match(route.to_string().as_str()))
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_rd(&self, rd: &BgpRD) -> FilterItemMatchResult {
        match self {
            FilterItem::RD(rdf) => (rdf == rd).into(),
            FilterItem::Num(n) => {
                FilterItemMatchResult::soft((rd.rdh as u64) == *n || (rd.rdl as u64) == *n)
            }
            FilterItem::Regexp(fp) => {
                FilterItemMatchResult::soft(fp.re.is_match(rd.to_string().as_str()))
            }
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_attr(&self, attr: &BgpAttrs) -> FilterItemMatchResult {
        match self {
            FilterItem::NHV4(nh) => match attr.nexthop {
                BgpAddr::V4(ref mnh) => nh.in_subnet(mnh).into(),
                BgpAddr::V4RD(ref mnh) => nh.in_subnet(&mnh.addr).into(),
                _ => FilterItemMatchResult::Unknown,
            },
            FilterItem::NHV6(nh) => match attr.nexthop {
                BgpAddr::V6(ref mnh) => nh.in_subnet(mnh).into(),
                BgpAddr::V6RD(ref mnh) => nh.in_subnet(&mnh.addr).into(),
                _ => FilterItemMatchResult::Unknown,
            },
            FilterItem::Community(cflt) => attr.comms.value.contains(cflt).into(),
            FilterItem::ExtCommunity(_) => {
                let mut ret = FilterItemMatchResult::Unknown;
                if attr.extcomms.value.is_empty() {
                    return ret;
                }
                for ec in attr.extcomms.value.iter() {
                    match ec.match_item(self) {
                        FilterItemMatchResult::Unknown => {}
                        FilterItemMatchResult::Yes => {
                            if ret == FilterItemMatchResult::Unknown {
                                ret = FilterItemMatchResult::Yes
                            }
                        }
                        n => {
                            ret = n;
                        }
                    }
                }
                ret
            }
            FilterItem::Regexp(fr) => FilterItemMatchResult::soft(
                fr.re.is_match(attr.origin.to_string().as_str())
                    || fr.re.is_match(attr.nexthop.to_string().as_str())
                    || fr.re.is_match(attr.aspath.to_string().as_str())
                    || fr.re.is_match(attr.comms.to_string().as_str())
                    || fr.re.is_match(attr.lcomms.to_string().as_str())
                    || fr.re.is_match(attr.extcomms.to_string().as_str()),
            ),
            FilterItem::ASPath(aspflt) => match aspflt {
                FilterASPath::Empty => (attr.aspath.value.len() == 0).into(),
                FilterASPath::FullMatch(asp) => (attr.aspath.value == asp.value).into(),
                FilterASPath::Contains(asp) => {
                    if asp.value.len() > attr.aspath.value.len() {
                        FilterItemMatchResult::No
                    } else if asp.value.len() == attr.aspath.value.len() {
                        (attr.aspath.value == asp.value).into()
                    } else {
                        for idx in 0..(attr.aspath.value.len() - asp.value.len() + 1) {
                            if attr.aspath.value[idx..(idx + asp.value.len())] == asp.value {
                                return FilterItemMatchResult::Yes;
                            }
                        }
                        FilterItemMatchResult::No
                    }
                }
                FilterASPath::StartsWith(asp) => {
                    if asp.value.len() > attr.aspath.value.len() {
                        FilterItemMatchResult::No
                    } else {
                        (asp.value == attr.aspath.value[0..asp.value.len()]).into()
                    }
                }
                FilterASPath::EndsWith(asp) => {
                    if asp.value.len() > attr.aspath.value.len() {
                        FilterItemMatchResult::No
                    } else {
                        (asp.value
                            == attr.aspath.value[attr.aspath.value.len() - asp.value.len()..])
                            .into()
                    }
                }
            },
            _ => FilterItemMatchResult::Unknown,
        }
    }
    fn get_subnet_range<T: FilterMatchRoute>(&self) -> Option<std::ops::RangeInclusive<T>> {
        T::get_subnet_range(self)
    }
    fn get_supernet_range<T: FilterMatchRoute>(&self) -> Option<std::ops::RangeInclusive<T>> {
        T::get_supernet_range(self)
    }
}

impl FilterTerm {
    pub fn parse(itemstr: &str) -> Option<FilterTerm> {
        if itemstr.len() < 1 {
            return None;
        };
        let fchr = match itemstr.chars().nth(0) {
            Some(c) => c,
            None => ' ',
        };
        if (fchr == '+' || fchr == '-') && itemstr.len() > 1 {
            match FilterItem::parse(&itemstr[1..]) {
                FilterItem::None => None,
                n => Some(FilterTerm {
                    predicate: if fchr == '+' {
                        FilterItemMatchResult::Yes
                    } else {
                        FilterItemMatchResult::No
                    },
                    item: n,
                }),
            }
        } else {
            match FilterItem::parse(itemstr) {
                FilterItem::None => None,
                n => Some(FilterTerm {
                    predicate: FilterItemMatchResult::Unknown,
                    item: n,
                }),
            }
        }
    }
    pub fn match_attr(&self, attr: &BgpAttrs) -> FilterItemMatchResult {
        match self.item.match_attr(attr) {
            FilterItemMatchResult::No => match self.predicate {
                FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                FilterItemMatchResult::Yes => FilterItemMatchResult::No,
            },
            FilterItemMatchResult::Yes => match self.predicate {
                FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                FilterItemMatchResult::No => FilterItemMatchResult::No,
                FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
            },
            _ => FilterItemMatchResult::Unknown,
        }
    }
    pub fn match_route<T: FilterMatchRoute>(
        &self,
        route: &T,
        attr: &BgpAttrs,
    ) -> FilterItemMatchResult {
        match route.match_item(&self.item) {
            FilterItemMatchResult::No => match self.predicate {
                FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                FilterItemMatchResult::Yes => FilterItemMatchResult::No,
            },
            FilterItemMatchResult::Yes => match self.item.match_attr(attr) {
                FilterItemMatchResult::No => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::No,
                },
                FilterItemMatchResult::Yes => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::No,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
                _ => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
            },
            FilterItemMatchResult::Unknown => match self.item.match_attr(attr) {
                FilterItemMatchResult::No => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::No,
                },
                FilterItemMatchResult::Yes => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::No,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
                _ => FilterItemMatchResult::Unknown,
            },
        }
    }
    pub fn match_super_route<T: FilterMatchRoute>(
        &self,
        route: &T,
        attr: &BgpAttrs,
    ) -> FilterItemMatchResult {
        match route.match_super_item(&self.item) {
            FilterItemMatchResult::No => match self.predicate {
                FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                FilterItemMatchResult::Yes => FilterItemMatchResult::No,
            },
            FilterItemMatchResult::Yes => match self.item.match_attr(attr) {
                FilterItemMatchResult::No => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::No,
                },
                FilterItemMatchResult::Yes => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::No,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
                _ => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
            },
            FilterItemMatchResult::Unknown => match self.item.match_attr(attr) {
                FilterItemMatchResult::No => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::No,
                    FilterItemMatchResult::No => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::No,
                },
                FilterItemMatchResult::Yes => match self.predicate {
                    FilterItemMatchResult::Unknown => FilterItemMatchResult::Yes,
                    FilterItemMatchResult::No => FilterItemMatchResult::No,
                    FilterItemMatchResult::Yes => FilterItemMatchResult::Yes,
                },
                _ => FilterItemMatchResult::Unknown,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn test_ribfilter_fi_ipv4_host() {
        assert_eq!(
            FilterItem::parse("10.6.7.8"),
            FilterItem::V4(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 8), 32))
        );
    }
    #[test]
    fn test_ribfilter_fi_ipv4_net() {
        assert_eq!(
            FilterItem::parse("10.6.7.0/24"),
            FilterItem::V4(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 24))
        );
    }
    #[test]
    fn test_ribfilter_fi_ipv6_host() {
        assert_eq!(
            FilterItem::parse("2c0a:dead:beef:b00b::beef:b00b"),
            FilterItem::V6(BgpAddrV6::new(
                std::net::Ipv6Addr::new(0x2c0a, 0xdead, 0xbeef, 0xb00b, 0, 0, 0xbeef, 0xb00b),
                128
            ))
        );
    }
    #[test]
    fn test_ribfilter_fi_ipv6_net() {
        assert_eq!(
            FilterItem::parse("2c0a:dead:beef:b00b::/64"),
            FilterItem::V6(BgpAddrV6::new(
                std::net::Ipv6Addr::new(0x2c0a, 0xdead, 0xbeef, 0xb00b, 0, 0, 0, 0),
                64
            ))
        );
    }
    #[test]
    fn test_ribfilter_fi_nh_ipv4() {
        assert_eq!(
            FilterItem::parse("nh:10.6.7.0/24"),
            FilterItem::NHV4(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 24))
        );
    }
    #[test]
    fn test_ribfilter_fi_nh_ipv6() {
        assert_eq!(
            FilterItem::parse("nh:2c0a:dead:beef:b00b::/64"),
            FilterItem::NHV6(BgpAddrV6::new(
                std::net::Ipv6Addr::new(0x2c0a, 0xdead, 0xbeef, 0xb00b, 0, 0, 0, 0),
                64
            ))
        );
    }
    #[test]
    fn test_ribfilter_fi_rd() {
        assert_eq!(
            FilterItem::parse("rd:100:1000"),
            FilterItem::RD(BgpRD::new(100, 1000))
        );
    }
    #[test]
    fn test_ribfilter_fi_as() {
        assert_eq!(
            FilterItem::parse("as:"),
            FilterItem::ASPath(FilterASPath::Empty)
        );
        assert_eq!(
            FilterItem::parse("as:^"),
            FilterItem::ASPath(FilterASPath::Empty)
        );
        assert_eq!(
            FilterItem::parse("as:^$"),
            FilterItem::ASPath(FilterASPath::Empty)
        );
        assert_eq!(
            FilterItem::parse("as:$"),
            FilterItem::ASPath(FilterASPath::Empty)
        );
        assert_eq!(
            FilterItem::parse("as:2345"),
            FilterItem::ASPath(FilterASPath::Contains(BgpASpath::from(vec![2345])))
        );
        assert_eq!(
            FilterItem::parse("as:100,2345"),
            FilterItem::ASPath(FilterASPath::Contains(BgpASpath::from(vec![100, 2345])))
        );
        assert_eq!(
            FilterItem::parse("as:^2345"),
            FilterItem::ASPath(FilterASPath::StartsWith(BgpASpath::from(vec![2345])))
        );
        assert_eq!(
            FilterItem::parse("as:2345$"),
            FilterItem::ASPath(FilterASPath::EndsWith(BgpASpath::from(vec![2345])))
        );
        assert_eq!(
            FilterItem::parse("as:^100,2345$"),
            FilterItem::ASPath(FilterASPath::FullMatch(BgpASpath::from(vec![100, 2345])))
        );
    }
    #[test]
    fn test_ribfilter_fi_com() {
        assert_eq!(
            FilterItem::parse("community:100:2345"),
            FilterItem::Community(BgpCommunity::from(100, 2345))
        );
    }
    #[test]
    fn test_ribfilter_match_rd() {
        let mut flt = RouteFilter::new();
        flt.parse("rd:100:1000");
        eprintln!("len = {}", flt.terms.len());
        assert_eq!(flt.terms.len(), 1);
        let mut rt = WithRd::<BgpAddrV4> {
            rd: BgpRD::new(100, 1000),
            prefix: BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 24),
        };
        let attrs = BgpAttrs::new();
        assert_eq!(
            flt.terms[0].match_route(&rt, &attrs),
            FilterItemMatchResult::Yes
        );
        assert_eq!(flt.match_route(&rt, &attrs), FilterItemMatchResult::Yes);
        rt.rd.rdh = 10000;
        assert_eq!(flt.match_route(&rt, &attrs), FilterItemMatchResult::No);
        flt.parse("10.0.0.0/8");
        rt.rd.rdh = 100;
        assert_eq!(flt.match_route(&rt, &attrs), FilterItemMatchResult::Yes);
    }
    #[test]
    fn test_ribfilter_match_subnet1() {
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.0/8");
        assert_eq!(flt.terms.len(), 1);
        let attrs = BgpAttrs::new();
        assert_eq!(
            flt.terms[0].match_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
        assert_eq!(
            flt.terms[0].match_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 8),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
        assert_eq!(
            flt.terms[0].match_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                &attrs
            ),
            FilterItemMatchResult::No
        );
        assert_eq!(
            flt.terms[0].match_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 7),
                &attrs
            ),
            FilterItemMatchResult::No
        );
        flt.terms.clear();
        flt.parse("213.0.0.0/8");
        assert_eq!(
            flt.terms[0].match_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(213, 140, 243, 0), 25),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
    }
    #[test]
    fn test_ribfilter_match_supernet() {
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.1");
        assert_eq!(flt.terms.len(), 1);
        let attrs = BgpAttrs::new();
        assert_eq!(
            flt.terms[0].match_super_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
        assert_eq!(
            flt.terms[0].match_super_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 8),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
        assert_eq!(
            flt.terms[0].match_super_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                &attrs
            ),
            FilterItemMatchResult::No
        );
        assert_eq!(
            flt.terms[0].match_super_route(
                &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                &attrs
            ),
            FilterItemMatchResult::Yes
        );
    }
    #[test]
    fn test_ribfilter_iter1() {
        assert!(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 16)
            .contains(&BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32)));
        assert!(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 16)
            .contains(&BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24)));
        let mut safi = BgpRIBSafi::<BgpAddrV4>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs = Arc::new(BgpAttrs::new());
        safi.handle_updates_afi(
            0,
            &[
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
            ],
            attrs,
        );
        assert_eq!(safi.len(), 3);
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.0/25");
        println!("{:?}", flt.terms);
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 1);
        flt.terms.clear();
        flt.parse("10.0.0.0/16");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 2);
        flt.terms.clear();
        flt.parse("11.0.0.0/16");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 1);
        flt.terms.clear();
        flt.parse("12.0.0.0/16");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 0);
    }
    #[test]
    fn test_ribfilter_num1() {
        let mut safi = BgpRIBSafi::<WithRd<BgpAddrV4>>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs = Arc::new(BgpAttrs::new());
        safi.handle_updates_afi(
            0,
            &[
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(1001, 100),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                ),
            ],
            attrs,
        );
        assert_eq!(safi.len(), 4);
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.0/25");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 2);
        flt.terms.clear();
        flt.parse("10.0.0.0/16");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 3);
        flt.terms.clear();
        flt.parse("rd:100:1000");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 3);
        flt.terms.clear();
        flt.parse("rd:100:1000 10.0.0.0/16");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 2);
        flt.terms.clear();
        flt.parse("100");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        flt.terms.clear();
        flt.parse("1001");
        assert_eq!(flt.terms.len(), 1);
        println!("{:?}", flt.terms);
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 1);
        flt.terms.clear();
        flt.parse("1000");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 3);
    }
    #[test]
    fn test_ribfilter_re1() {
        let mut safi = BgpRIBSafi::<WithRd<BgpAddrV4>>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs = Arc::new(BgpAttrs::new());
        safi.handle_updates_afi(
            0,
            &[
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(100, 1000),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                ),
                WithRd::<BgpAddrV4>::new(
                    BgpRD::new(1001, 100),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                ),
            ],
            attrs,
        );
        assert_eq!(safi.len(), 4);
        let mut flt = RouteFilter::new();
        flt.parse("re:10\\.0\\.0");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 3);
        flt.terms.clear();
        flt.parse("rd:100:1000");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 3);
    }
    #[test]
    fn test_ribfilter_extrt1() {
        let mut safi = BgpRIBSafi::<WithRd<BgpAddrV4>>::new(10, HistoryChangeMode::EveryUpdate);
        {
            let attrs1 = BgpAttrs {
                origin: BgpAttrOrigin::Incomplete,
                nexthop: BgpAddr::None,
                atomicaggregate: None,
                aggregatoras: None,
                originator: None,
                clusterlist: None,
                pmsi_ta: None,
                aspath: Arc::new(BgpASpath::new()),
                comms: Arc::new(BgpCommunityList::new()),
                lcomms: Arc::new(BgpLargeCommunityList::new()),
                extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![BgpExtCommunity {
                    ctype: 0,
                    subtype: 2,
                    a: 200,
                    b: 300,
                }])),
                med: None,
                localpref: None,
            };
            safi.handle_updates_afi(
                0,
                &[
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1001, 100),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                    ),
                ],
                Arc::new(attrs1),
            );
            let attrs2 = BgpAttrs {
                origin: BgpAttrOrigin::Incomplete,
                nexthop: BgpAddr::None,
                aspath: Arc::new(BgpASpath::new()),
                comms: Arc::new(BgpCommunityList::new()),
                lcomms: Arc::new(BgpLargeCommunityList::new()),
                extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![BgpExtCommunity {
                    ctype: 0,
                    subtype: 2,
                    a: 400,
                    b: 500,
                }])),
                med: None,
                localpref: None,
                aggregatoras: None,
                atomicaggregate: None,
                clusterlist: None,
                originator: None,
                pmsi_ta: None,
            };
            safi.handle_updates_afi(
                0,
                &[
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 32),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 2), 32),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(100, 1000),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 1, 0), 24),
                    ),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1001, 100),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 32),
                    ),
                ],
                Arc::new(attrs2),
            );
        }
        assert_eq!(safi.len(), 8);
        let mut flt = RouteFilter::new();
        /*
        flt.parse("re:10\\.0\\.0");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 5);
        flt.terms.clear();
        flt.parse("rt:200:300");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        flt.terms.clear();
        flt.parse("rt:201:300");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 0);
        flt.terms.clear();
        flt.parse("rt:400");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        flt.terms.clear();
        flt.parse("rt:500");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        flt.terms.clear();
        flt.parse("rt:400:500");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        */
        flt.terms.clear();
        flt.parse("rt:400:500 10.0.0.0/24");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 2);
    }
    #[test]
    fn test_ribfilter_range1() {
        let mut safi = BgpRIBSafi::<BgpAddrV4>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs1 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![BgpExtCommunity {
                ctype: 0,
                subtype: 2,
                a: 200,
                b: 300,
            }])),
            med: None,
            localpref: None,
        };
        safi.handle_updates_afi(
            0,
            &[
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 32),
            ],
            Arc::new(attrs1),
        );
        assert_eq!(safi.len(), 5);
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.0/24");
        assert_eq!(flt.iter_nets(&safi, 10, false).count(), 4);
        for (ref key, ref _value) in safi.items.range(
            &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24)
                ..&BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 1, 0), 24),
        ) {
            eprintln!("{}", key);
        }
        assert_eq!(
            safi.items
                .range(
                    &BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24)
                        ..&BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 24)
                )
                .count(),
            3
        );
    }
    #[test]
    fn test_ribfilter_range2() {
        let mut safi = BgpRIBSafi::<BgpAddrV4>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs1 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![BgpExtCommunity {
                ctype: 0,
                subtype: 2,
                a: 200,
                b: 300,
            }])),
            med: None,
            localpref: None,
        };
        safi.handle_updates_afi(
            0,
            &[
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 32),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 32),
            ],
            Arc::new(attrs1),
        );
        assert_eq!(safi.len(), 5);
        let mut flt = RouteFilter::new();
        flt.parse("10.0.0.0/24");
        for (ref key, ref _value) in flt.iter_nets(&safi, 10, false) {
            eprintln!("{}", key);
        }
    }
    #[test]
    fn test_ribfilter_range3() {
        let mut safi =
            BgpRIBSafi::<Labeled<WithRd<BgpAddrV4>>>::new(10, HistoryChangeMode::EveryUpdate);
        let attrs1 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![BgpExtCommunity {
                ctype: 0,
                subtype: 2,
                a: 200,
                b: 300,
            }])),
            med: None,
            localpref: None,
        };
        safi.handle_updates_afi(
            0,
            &[
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![1]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 1),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![2]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 1),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![3]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 3),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![4]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 4),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(11, 0, 0, 1), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![5]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 5),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![6]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 6),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![7]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 7),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 32),
                    ),
                ),
                Labeled::<WithRd<BgpAddrV4>>::new(
                    MplsLabels::fromvec(vec![8]),
                    WithRd::<BgpAddrV4>::new(
                        BgpRD::new(1, 4),
                        BgpAddrV4::new(std::net::Ipv4Addr::new(12, 0, 0, 1), 32),
                    ),
                ),
            ],
            Arc::new(attrs1),
        );
        assert_eq!(safi.len(), 8);
        assert_eq!(
            RouteFilter::fromstr("10.0.0.0/24")
                .iter_nets(&safi, 10, false)
                .count(),
            6
        );
        assert_eq!(
            RouteFilter::fromstr("rd:1:4")
                .iter_nets(&safi, 10, false)
                .count(),
            2
        );
        assert_eq!(
            RouteFilter::fromstr("rd:1:1")
                .iter_nets(&safi, 10, false)
                .count(),
            2
        );
        assert_eq!(
            RouteFilter::fromstr("10.0.0.1")
                .iter_nets(&safi, 10, false)
                .count(),
            2
        );
    }
    #[test]
    fn test_ribfilter_4() {
        let attrs1 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![
                BgpExtCommunity::rt_asn(1, 1),
            ])),
            med: None,
            localpref: None,
        };
        let attrs2 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![
                BgpExtCommunity::rt_asn(1, 2),
            ])),
            med: None,
            localpref: None,
        };
        let r1 = Labeled::<WithRd<BgpAddrV4>>::new(
            MplsLabels::fromvec(vec![1]),
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 32),
            ),
        );
        let r2 = Labeled::<WithRd<BgpAddrV4>>::new(
            MplsLabels::fromvec(vec![1]),
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0),
            ),
        );
        let rf = RouteFilter::fromstr("10.0.0.0/24 rt:1:1");
        assert_eq!(rf.match_route(&r1, &attrs1), FilterItemMatchResult::Yes);
        assert_eq!(rf.match_route(&r1, &attrs2), FilterItemMatchResult::Unknown);
        assert!(rf.match_route(&r2, &attrs1) != FilterItemMatchResult::Yes);
        assert!(rf.match_route(&r2, &attrs2) != FilterItemMatchResult::Yes);
        assert_eq!(
            rf.match_super_route(&r2, &attrs1),
            FilterItemMatchResult::Yes
        );
        assert!(rf.match_super_route(&r2, &attrs2) != FilterItemMatchResult::Yes);
    }
    #[test]
    fn test_ribfilter_mvpn_1() {
        let attrs1 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![
                BgpExtCommunity::rt_asn(1, 1),
            ])),
            med: None,
            localpref: None,
        };
        let attrs2 = BgpAttrs {
            origin: BgpAttrOrigin::Incomplete,
            nexthop: BgpAddr::None,
            atomicaggregate: None,
            aggregatoras: None,
            originator: None,
            clusterlist: None,
            pmsi_ta: None,
            aspath: Arc::new(BgpASpath::new()),
            comms: Arc::new(BgpCommunityList::new()),
            lcomms: Arc::new(BgpLargeCommunityList::new()),
            extcomms: Arc::new(BgpExtCommunityList::from_vec(vec![
                BgpExtCommunity::rt_asn(1, 2),
            ])),
            med: None,
            localpref: None,
        };
        let r1 = BgpMVPN::T5(BgpMVPN5 {
            rd: BgpRD::new(1, 1),
            source: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1)),
            group: std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 1, 1, 1)),
        });
        let r2 = BgpMVPN::T5(BgpMVPN5 {
            rd: BgpRD::new(2, 1),
            source: std::net::IpAddr::V4(std::net::Ipv4Addr::new(11, 1, 1, 1)),
            group: std::net::IpAddr::V4(std::net::Ipv4Addr::new(225, 1, 1, 1)),
        });
        let rf1 = RouteFilter::fromstr("10.1.1.0/24");
        assert_eq!(rf1.match_route(&r1, &attrs1), FilterItemMatchResult::Yes);
        assert_eq!(rf1.match_route(&r2, &attrs2), FilterItemMatchResult::No);
        let rf2 = RouteFilter::fromstr("11.1.1.0/24");
        assert_eq!(rf2.match_route(&r1, &attrs1), FilterItemMatchResult::No);
        assert_eq!(rf2.match_route(&r2, &attrs2), FilterItemMatchResult::Yes);
        let rf1 = RouteFilter::fromstr("224.1.1.0/24");
        assert_eq!(rf1.match_route(&r1, &attrs1), FilterItemMatchResult::Yes);
        assert_eq!(rf1.match_route(&r2, &attrs2), FilterItemMatchResult::No);
        let rf2 = RouteFilter::fromstr("225.1.1.0/24");
        assert_eq!(rf2.match_route(&r1, &attrs1), FilterItemMatchResult::No);
        assert_eq!(rf2.match_route(&r2, &attrs2), FilterItemMatchResult::Yes);
    }
}
