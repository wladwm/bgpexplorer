use chrono::prelude::*;

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Timestamp(DateTime<Local>);
impl Timestamp {
    pub fn now() -> Self {
        Timestamp(Local::now())
    }
}
impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0,)
    }
}
impl std::convert::From<DateTime<Local>> for Timestamp {
    fn from(t: DateTime<Local>) -> Self {
        Timestamp(t)
    }
}
impl std::ops::Deref for Timestamp {
    type Target = DateTime<Local>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.0.timestamp_millis())
    }
}
impl<'de> serde::de::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        Ok(Timestamp(Local.timestamp_millis(i64::deserialize(deserializer)?)))
    }
}
