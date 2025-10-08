use chrono::prelude::*;
use chrono::{Local, LocalResult, TimeZone};

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Timestamp(DateTime<Local>);
impl Timestamp {
    pub fn now() -> Self {
        Timestamp(Local::now())
    }
    pub fn timestamp_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }
    pub fn cut_millis(&self, s: u64) -> Timestamp {
        let mut m = self.0.timestamp_millis();
        m -= m % (s as i64);
        match Local.timestamp_millis_opt(m) {
            LocalResult::Single(dt) => Timestamp(dt.into()),
            LocalResult::Ambiguous(t1, _) => Timestamp(t1.into()),
            _ => return *self,
        }
    }
}
impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::convert::From<DateTime<Local>> for Timestamp {
    fn from(t: DateTime<Local>) -> Self {
        Timestamp(t)
    }
}
impl std::convert::Into<DateTime<Local>> for Timestamp {
    fn into(self) -> DateTime<Local> {
        self.0
    }
}
impl std::ops::Deref for Timestamp {
    type Target = DateTime<Local>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::str::FromStr for Timestamp {
    type Err = chrono::format::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ts) = s.parse() {
            match Local.timestamp_millis_opt(ts) {
                LocalResult::Single(dt) => return Ok(dt.into()),
                LocalResult::Ambiguous(t1, _) => return Ok(t1.into()),
                LocalResult::None => return Ok(Timestamp(Local::now())),
            }
        }
        Ok(Timestamp(DateTime::parse_from_rfc3339(s)?.into()))
    }
}
impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.timestamp_millis())
    }
}
impl<'de> serde::de::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        Ok(Timestamp(
            match Local.timestamp_millis_opt(i64::deserialize(deserializer)?) {
                LocalResult::Single(dt) => dt,
                LocalResult::Ambiguous(t1, _) => t1,
                LocalResult::None => Local::now(),
            },
        ))
    }
}
