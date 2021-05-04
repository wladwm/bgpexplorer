use serde::ser::{SerializeMap, SerializeStruct};

use crate::bgprib::*;
use zettabgp::prelude::*;

impl serde::Serialize for BgpAttrs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpAttrs", 5)?;
        state.serialize_field("origin", &self.origin)?;
        state.serialize_field("nexthop", &self.nexthop)?;
        state.serialize_field::<BgpASpath>("aspath", &self.aspath)?;
        if self.comms.value.len() > 0 {
            state.serialize_field::<BgpCommunityList>("communities", &self.comms)?;
        }
        if self.lcomms.value.len() > 0 {
            state.serialize_field::<BgpLargeCommunityList>("large_communities", &self.lcomms)?;
        }
        if self.extcomms.value.len() > 0 {
            state.serialize_field::<BgpExtCommunityList>("extcommunities", &self.extcomms)?;
        }
        if let Some(ref n) = self.med {
            state.serialize_field("med", n)?;
        };
        if let Some(ref n) = self.localpref {
            state.serialize_field("localpref", n)?;
        };
        if let Some(ref n) = self.atomicaggregate {
            state.serialize_field("atomicaggregate", n)?;
        };
        if let Some(ref n) = self.aggregatoras {
            state.serialize_field("aggregatoras", n)?;
        };
        if let Some(ref n) = self.originator {
            state.serialize_field("originator", n)?;
        };
        if let Some(ref n) = self.clusterlist {
            state.serialize_field::<BgpClusterList>("clusterlist", n)?;
        };
        if let Some(ref n) = self.pmsi_ta {
            state.serialize_field::<BgpPMSITunnel>("pmsi_tunnel_attributes", n)?;
        };
        state.end()
    }
}

impl serde::Serialize for BgpAttrEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpAttrEntry", 2)?;
        state.serialize_field("active", &self.active)?;
        state.serialize_field::<BgpAttrs>("attrs", &self.attrs)?;
        if let Some(ref lbls) = self.labels {
            state.serialize_field("labels", lbls)?;
        }
        state.end()
    }
}
impl serde::Serialize for BgpAttrHistory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(self.items.len()))?;
        for (k, v) in self.items.iter() {
            state.serialize_entry(&k.format("%Y-%m-%dT%H:%M:%S").to_string(), v)?;
        }
        state.end()
    }
}
