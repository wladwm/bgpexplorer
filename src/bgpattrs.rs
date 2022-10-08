use crate::bgprib::BgpRIB;
use serde::ser::SerializeStruct;
use std::rc::Rc;
use std::sync::{Mutex};
use zettabgp::prelude::*;

lazy_static! {
    static ref RIB: Mutex<Option<BgpRIB>> = Mutex::new(None);
}
pub fn rib_set(rib: BgpRIB) {
    *(RIB.lock().unwrap()) = Some(rib)
}
pub fn rib_take() -> BgpRIB {
    RIB.lock().unwrap().take().unwrap()
}
pub fn rib_get<'a>() -> std::sync::MutexGuard<'a,Option<BgpRIB>> {
    RIB.lock().unwrap()
}

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
enum BgpAttrsField {
    Origin,
    Nexthop,
    Aspath,
    Comms,
    LComms,
    ExtComms,
    Med,
    Localpref,
    Atomicaggregate,
    Aggregatoras,
    Originator,
    Clusterlist,
    PmsiTa,
}
const BA_VARS: [&'static str; 13] = [
    "Origin",
    "Nexthop",
    "Aspath",
    "Comms",
    "LComms",
    "ExtComms",
    "Med",
    "Localpref",
    "Atomicaggregate",
    "Aggregatoras",
    "Originator",
    "Clusterlist",
    "PmsiTa",
];
impl<'de> serde::de::Deserialize<'de> for BgpAttrsField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct FieldVisitor;
        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = BgpAttrsField;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "one of {:?}", BA_VARS)
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<BgpAttrsField, E> {
                match value {
                    "Origin" => Ok(BgpAttrsField::Origin),
                    "Nexthop" => Ok(BgpAttrsField::Nexthop),
                    "Aspath" => Ok(BgpAttrsField::Aspath),
                    "Comms" => Ok(BgpAttrsField::Comms),
                    "LComms" => Ok(BgpAttrsField::LComms),
                    "ExtComms" => Ok(BgpAttrsField::ExtComms),
                    "Med" => Ok(BgpAttrsField::Med),
                    "Localpref" => Ok(BgpAttrsField::Localpref),
                    "Atomicaggregate" => Ok(BgpAttrsField::Atomicaggregate),
                    "Aggregatoras" => Ok(BgpAttrsField::Aggregatoras),
                    "Originator" => Ok(BgpAttrsField::Originator),
                    "Clusterlist" => Ok(BgpAttrsField::Clusterlist),
                    "PmsiTa" => Ok(BgpAttrsField::PmsiTa),
                    _ => Err(serde::de::Error::unknown_field(value, &BA_VARS)),
                }
            }
        }
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
pub(crate) struct BgpAttrsVisitor;
impl<'de> serde::de::Visitor<'de> for BgpAttrsVisitor {
    type Value = BgpAttrs;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct BgpAttrs")
    }
    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::SeqAccess<'de>,
    {
        let origin = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let nexthop = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        let aspath = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        let comms = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
        let lcomms = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
        let extcomms = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
        let med = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
        let localpref = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(7, &self))?;
        let atomicaggregate = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(8, &self))?;
        let aggregatoras = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(9, &self))?;
        let originator = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(10, &self))?;
        let clusterlist: Option<BgpClusterList> = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(11, &self))?;
        let pmsi_ta: Option<BgpPMSITunnel> = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(12, &self))?;
        let mut mrib = rib_get();
        match (*mrib).as_mut() {
            None => Ok(BgpAttrs::new()),
            Some(rib) => Ok(BgpAttrs {
                origin,
                nexthop,
                aspath: rib.pathes.get(Rc::new(aspath)).unwrap(),
                comms: rib.comms.get(Rc::new(comms)).unwrap(),
                lcomms: rib.lcomms.get(Rc::new(lcomms)).unwrap(),
                extcomms: rib.extcomms.get(Rc::new(extcomms)).unwrap(),
                med,
                localpref,
                atomicaggregate,
                aggregatoras,
                originator,
                clusterlist: clusterlist.map(|x| rib.clusters.get(Rc::new(x)).unwrap()),
                pmsi_ta: pmsi_ta.map(|x| rib.pmsi_ta_s.get(Rc::new(x)).unwrap()),
            }),
        }
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        let mut origin = None;
        let mut nexthop = None;
        let mut aspath = None;
        let mut comms = None;
        let mut lcomms = None;
        let mut extcomms = None;
        let mut med = None;
        let mut localpref = None;
        let mut atomicaggregate = None;
        let mut aggregatoras = None;
        let mut originator = None;
        let mut clusterlist: Option<Option<BgpClusterList>> = None;
        let mut pmsi_ta: Option<Option<BgpPMSITunnel>> = None;
        while let Some(key) = map.next_key()? {
            match key {
                BgpAttrsField::Origin => {
                    if origin.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[0]));
                    }
                    origin = Some(map.next_value()?);
                }
                BgpAttrsField::Nexthop => {
                    if nexthop.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[1]));
                    }
                    nexthop = Some(map.next_value()?);
                }
                BgpAttrsField::Aspath => {
                    if aspath.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[2]));
                    }
                    aspath = Some(map.next_value()?);
                }
                BgpAttrsField::Comms => {
                    if comms.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[3]));
                    }
                    comms = Some(map.next_value()?);
                }
                BgpAttrsField::LComms => {
                    if lcomms.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[4]));
                    }
                    lcomms = Some(map.next_value()?);
                }
                BgpAttrsField::ExtComms => {
                    if extcomms.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[5]));
                    }
                    extcomms = Some(map.next_value()?);
                }
                BgpAttrsField::Med => {
                    if med.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    med = Some(map.next_value()?);
                }
                BgpAttrsField::Localpref => {
                    if localpref.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    localpref = Some(map.next_value()?);
                }
                BgpAttrsField::Atomicaggregate => {
                    if atomicaggregate.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    atomicaggregate = Some(map.next_value()?);
                }
                BgpAttrsField::Aggregatoras => {
                    if aggregatoras.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    aggregatoras = Some(map.next_value()?);
                }
                BgpAttrsField::Originator => {
                    if originator.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    originator = Some(map.next_value()?);
                }
                BgpAttrsField::Clusterlist => {
                    if clusterlist.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    clusterlist = Some(map.next_value()?);
                }
                BgpAttrsField::PmsiTa => {
                    if pmsi_ta.is_some() {
                        return Err(serde::de::Error::duplicate_field(BA_VARS[6]));
                    }
                    pmsi_ta = Some(map.next_value()?);
                }
            }
        }

        let origin = origin.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[0]))?;
        let nexthop = nexthop.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[1]))?;
        let aspath = aspath.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[2]))?;
        let comms = comms.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[3]))?;
        let lcomms = lcomms.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[4]))?;
        let extcomms = extcomms.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[5]))?;
        let med = med.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[6]))?;
        let localpref = localpref.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[7]))?;
        let atomicaggregate =
            atomicaggregate.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[8]))?;
        let aggregatoras =
            aggregatoras.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[9]))?;
        let originator = originator.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[10]))?;
        let clusterlist =
            clusterlist.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[11]))?;
        let pmsi_ta = pmsi_ta.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[12]))?;
        let mut mrib = rib_get();
        match (*mrib).as_mut() {
            None => Ok(BgpAttrs::new()),
            Some(rib) => Ok(BgpAttrs {
                origin,
                nexthop,
                aspath: rib.pathes.get(Rc::new(aspath)).unwrap(),
                comms: rib.comms.get(Rc::new(comms)).unwrap(),
                lcomms: rib.lcomms.get(Rc::new(lcomms)).unwrap(),
                extcomms: rib.extcomms.get(Rc::new(extcomms)).unwrap(),
                med,
                localpref,
                atomicaggregate,
                aggregatoras,
                originator,
                clusterlist: clusterlist.map(|x| rib.clusters.get(Rc::new(x)).unwrap()),
                pmsi_ta: pmsi_ta.map(|x| rib.pmsi_ta_s.get(Rc::new(x)).unwrap()),
            }),
        }
    }
}
impl serde::Serialize for BgpAttrs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("BgpAttrs", 13)?;
        map.serialize_field(BA_VARS[0], &self.origin)?;
        map.serialize_field(BA_VARS[1], &self.nexthop)?;
        map.serialize_field(BA_VARS[2], self.aspath.as_ref())?;
        map.serialize_field(BA_VARS[3], self.comms.as_ref())?;
        map.serialize_field(BA_VARS[4], self.lcomms.as_ref())?;
        map.serialize_field(BA_VARS[5], self.extcomms.as_ref())?;
        map.serialize_field(BA_VARS[6], &self.med)?;
        map.serialize_field(BA_VARS[7], &self.localpref)?;
        map.serialize_field(BA_VARS[8], &self.atomicaggregate)?;
        map.serialize_field(BA_VARS[9], &self.aggregatoras)?;
        map.serialize_field(BA_VARS[10], &self.originator)?;
        map.serialize_field(BA_VARS[11], &self.clusterlist.as_ref().map(|x| x.as_ref()))?;
        map.serialize_field(BA_VARS[12], &self.pmsi_ta.as_ref().map(|x| x.as_ref()))?;
        map.end()
    }
}
impl<'de> serde::de::Deserialize<'de> for BgpAttrs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_struct("BgpAttrs", &BA_VARS, BgpAttrsVisitor)
    }
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
#[derive(Debug, Clone)]
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
impl serde::Serialize for BgpAttrEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("BgpAttrEntry", 3)?;
        map.serialize_field(BAE_VARS[0], &self.active)?;
        map.serialize_field(BAE_VARS[1], self.attrs.as_ref())?;
        map.serialize_field(BAE_VARS[2], &self.labels)?;
        map.end()
    }
}
enum BgpAttrEntryField {
    Active,
    Attrs,
    Labels,
}
const BAE_VARS: [&'static str; 3] = ["Active", "Attrs", "Labels"];
impl<'de> serde::de::Deserialize<'de> for BgpAttrEntryField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct FieldVisitor;
        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = BgpAttrEntryField;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "one of {:?}", BAE_VARS)
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<BgpAttrEntryField, E> {
                match value {
                    "Active" => Ok(BgpAttrEntryField::Active),
                    "Attrs" => Ok(BgpAttrEntryField::Attrs),
                    "Labels" => Ok(BgpAttrEntryField::Labels),
                    _ => Err(serde::de::Error::unknown_field(value, &BAE_VARS)),
                }
            }
        }
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
struct BgpAttrEntryVisitor;
impl<'de> serde::de::Visitor<'de> for BgpAttrEntryVisitor {
    type Value = BgpAttrEntry;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct BgpAttrEntry")
    }
    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::SeqAccess<'de>,
    {
        let active = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let attrs = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        let labels = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        let mut mrib = rib_get();
        match (*mrib).as_mut() {
            None => Ok(BgpAttrEntry::new(active, Rc::new(attrs), labels)),
            Some(rib) => Ok(BgpAttrEntry {
                active,
                attrs: rib.attrs.get(Rc::new(attrs)).unwrap(),
                labels,
            }),
        }
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        let mut active = None;
        let mut attrs = None;
        let mut labels = None;
        while let Some(key) = map.next_key()? {
            match key {
                BgpAttrEntryField::Active => {
                    if active.is_some() {
                        return Err(serde::de::Error::duplicate_field(BAE_VARS[0]));
                    }
                    active = Some(map.next_value()?);
                }
                BgpAttrEntryField::Attrs => {
                    if attrs.is_some() {
                        return Err(serde::de::Error::duplicate_field(BAE_VARS[1]));
                    }
                    attrs = Some(map.next_value()?);
                }
                BgpAttrEntryField::Labels => {
                    if labels.is_some() {
                        return Err(serde::de::Error::duplicate_field(BAE_VARS[2]));
                    }
                    labels = Some(map.next_value()?);
                }
            }
        }

        let active = active.ok_or_else(|| serde::de::Error::missing_field(BA_VARS[0]))?;
        let attrs = attrs.ok_or_else(|| serde::de::Error::missing_field(BAE_VARS[1]))?;
        let labels = labels.ok_or_else(|| serde::de::Error::missing_field(BAE_VARS[2]))?;
        let mut mrib = rib_get();
        match (*mrib).as_mut() {
            None => Ok(BgpAttrEntry::new(active, Rc::new(attrs), labels)),
            Some(rib) => Ok(BgpAttrEntry {
                active,
                attrs: rib.attrs.get(Rc::new(attrs)).unwrap(),
                labels,
            }),
        }
    }
}
impl<'de> serde::de::Deserialize<'de> for BgpAttrEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_struct("BgpAttrEntry", &BAE_VARS, BgpAttrEntryVisitor)
    }
}
