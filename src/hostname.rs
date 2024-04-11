// use serde::{Deserialize, Serialize};
use std::{fmt, net::Ipv4Addr, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(pub String);

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Hostname {
    type Err = String;

    fn from_str(hostname: &str) -> Result<Self, Self::Err> {
        let valid_ip = hostname.parse::<Ipv4Addr>().is_ok();
        let valid_hostname = hostname_validator::is_valid(hostname);

        if !valid_ip && !valid_hostname {
            return Err("hostname is invalid".to_owned());
        }

        Ok(Hostname(hostname.to_owned()))
    }
}

impl PartialEq<&str> for Hostname {
    fn eq(&self, other: &&str) -> bool {
        &self.0 == other
    }
}

// impl Serialize for Hostname {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         serializer.serialize_str(&self.to_string())
//     }
// }

// impl<'de> Deserialize<'de> for Hostname {
//     fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let hostname = String::deserialize(deserializer)?;
//         Self::from_str(&hostname).map_err(serde::de::Error::custom)
//     }
// }
