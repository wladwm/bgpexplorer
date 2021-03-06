use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use whois_rust::WhoIs;

/// peer protocol mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMode {
    /// bgpexplorer connects to BGP router
    BgpActive,
    /// BGP router connects to bgpexplorer
    BgpPassive,
    /// BMP router connects to bgpexplorer
    BmpPassive,
    /// bgpexplorer connects to BMP router
    BmpActive,
}
/// history store mode variations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryChangeMode {
    /// every update recorded, even duplicates
    EveryUpdate,
    /// history record made only if route attributes is differ
    OnlyDiffer,
}

/// peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoPeer {
    pub routerid: Ipv4Addr,
    pub mode: PeerMode,
    pub peer: Option<SocketAddr>,
    pub protolisten: Option<SocketAddr>,
    pub bgppeeras: u32,
    pub flt_rd: Option<zettabgp::afi::BgpRD>
}
impl ProtoPeer {
    pub fn from_ini(
        svcsection: &std::collections::HashMap<
            std::string::String,
            std::option::Option<std::string::String>,
        >,
    ) -> Result<ProtoPeer, ErrorConfig> {
        if !svcsection.contains_key("mode") {
            return Err(ErrorConfig::from_str("Missing value 'mode'"));
        };
        let mode = match svcsection["mode"] {
            None => {
                return Err(ErrorConfig::from_str(
                    "No mode (bgpactive|bgppassive|bmpactive|bmppassive) specified",
                ));
            }
            Some(ref s) => s,
        };
        let peermode = mode.parse()?;
        let peer: Option<std::net::SocketAddr> = if svcsection.contains_key("peer") {
            match svcsection["peer"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid peer was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(_e) => {
                        let peerip: std::net::IpAddr = match s.parse() {
                            Err(_) => {
                                return Err(ErrorConfig::from_str("invalid peer was specified"));
                            }
                            Ok(v) => v,
                        };
                        Some(std::net::SocketAddr::new(
                            peerip,
                            if peermode == PeerMode::BmpActive {
                                632
                            } else {
                                179
                            },
                        ))
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            if peermode == PeerMode::BgpActive || peermode == PeerMode::BmpActive {
                // fatal error
                return Err(ErrorConfig::from_str("peer was not specified"));
            } else {
                None
            }
        };
        let protolisten: Option<SocketAddr> = if svcsection.contains_key("protolisten") {
            match svcsection["protolisten"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid protolisten was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(_e) => {
                        let peerip: IpAddr = match s.parse() {
                            Err(_) => {
                                return Err(ErrorConfig::from_str(
                                    "invalid protolisten was specified",
                                ));
                            }
                            Ok(v) => v,
                        };
                        Some(SocketAddr::new(
                            peerip,
                            if peermode == PeerMode::BmpPassive {
                                632
                            } else {
                                179
                            },
                        ))
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            if peermode == PeerMode::BgpPassive || peermode == PeerMode::BmpPassive {
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    if peermode == PeerMode::BmpPassive {
                        632
                    } else {
                        179
                    },
                ))
            } else {
                None
            }
        };
        let routerid: Ipv4Addr = if svcsection.contains_key("routerid") {
            match svcsection["routerid"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid routerid was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid routerid - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            Ipv4Addr::new(1, 1, 1, 1)
        };
        let bgppeeras: u32 = if svcsection.contains_key("peeras") {
            match svcsection["peeras"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid bgppeeras was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid bgp peer as - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            0
        };
        let flt_rd = if svcsection.contains_key("filter_rd") {
            match svcsection["filter_rd"] {
                None => {
                    None
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid bmp filter_rd - {}",
                            e
                        )));
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            Some(zettabgp::afi::BgpRD::new(0,0))
        };
        Ok(ProtoPeer {
            routerid: routerid,
            mode: peermode,
            peer: peer,
            protolisten: protolisten,
            bgppeeras: bgppeeras,
            flt_rd: flt_rd
        })
    }
}

#[derive(Debug, Clone)]
pub struct SvcConfig {
    pub httplisten: std::net::SocketAddr,
    pub httproot: String,
    pub historydepth: usize,
    pub httptimeout: u64,
    pub historymode: HistoryChangeMode,
    pub whoisconfig: WhoIs,
    pub whoisdb: String,
    pub whoisreqtimeout: u64,
    pub whoiscachesecs: i64,
    pub whoisdnses: Vec<std::net::SocketAddr>,
    pub peers: Vec<Arc<ProtoPeer>>,
    pub purge_after_withdraws: u64,
    pub purge_every: chrono::Duration,
}

#[derive(Debug)]
pub enum ErrorConfig {
    Static(&'static str),
    Str(String),
}
impl ErrorConfig {
    pub fn from_str(m: &'static str) -> Self {
        ErrorConfig::Static(m)
    }
    pub fn from_string(m: String) -> Self {
        ErrorConfig::Str(m)
    }
}
impl From<&'static str> for ErrorConfig {
    fn from(m: &'static str) -> Self {
        ErrorConfig::Static(m)
    }
}
impl fmt::Display for ErrorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ErrorConfig: {}",
            match self {
                ErrorConfig::Static(s) => s,
                ErrorConfig::Str(s) => s.as_str(),
            }
        )
    }
}

impl Error for ErrorConfig {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self)
    }
}

impl FromStr for PeerMode {
    type Err = ErrorConfig;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<&str> = s.split(' ').collect();
        match sp[0] {
            "bgpactive" => Ok(PeerMode::BgpActive),
            "bgppassive" => Ok(PeerMode::BgpPassive),
            "bmppassive" => Ok(PeerMode::BmpPassive),
            "bmpactive" => Ok(PeerMode::BmpActive),
            _ => Err(ErrorConfig::from_str("invalid mode")),
        }
    }
}

impl FromStr for HistoryChangeMode {
    type Err = ErrorConfig;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<&str> = s.split(' ').collect();
        match sp[0] {
            "every" => Ok(HistoryChangeMode::EveryUpdate),
            "differ" => Ok(HistoryChangeMode::OnlyDiffer),
            _ => Err(ErrorConfig::from_str("invalid history mode")),
        }
    }
}

impl SvcConfig {
    pub fn from_inifile(inifile: &str) -> Result<SvcConfig, ErrorConfig> {
        let conf = ini!(inifile);
        if !conf.contains_key("main") {
            return Err(ErrorConfig::from_str("Missing section 'main' in ini file"));
        }
        let mainsection = &conf["main"];
        let peers: Vec<Arc<ProtoPeer>> = conf
            .iter()
            .filter(|x| x.0 != "main")
            .filter_map(|x| ProtoPeer::from_ini(x.1).ok())
            .map(|x| Arc::new(x))
            .collect();
        if peers.len() < 1 {
            return Err(ErrorConfig::from_str("No valid peers or listens specified"));
        }
        let httplisten: std::net::SocketAddr = match (if mainsection.contains_key("httplisten") {
            match mainsection["httplisten"] {
                Some(ref s) => s.to_string(),
                None => "0.0.0.0:8080".to_string(),
            }
        } else {
            "0.0.0.0:8080".to_string()
        })
        .parse()
        {
            Ok(sa) => sa,
            Err(e) => {
                return Err(ErrorConfig::from_string(format!(
                    "Invalid httplisten - {}",
                    e
                )));
            }
        };
        let httptimeout = if mainsection.contains_key("httptimeout") {
            match mainsection["httptimeout"] {
                Some(ref s) => s.parse().unwrap_or(120),
                None => 120,
            }
        } else {
            120
        };
        let httproot = if mainsection.contains_key("httproot") {
            match mainsection["httproot"] {
                Some(ref s) => s.to_string(),
                None => "./contrib".to_string(),
            }
        } else {
            "./contrib".to_string()
        };
        let historydepth: usize = if mainsection.contains_key("historydepth") {
            match mainsection["historydepth"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid historydepth was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid historydepth - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            10
        };
        let historymode: HistoryChangeMode = if mainsection.contains_key("historymode") {
            match mainsection["historymode"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid historymode was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid historymode - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            HistoryChangeMode::OnlyDiffer
        };
        let purge_after_withdraws: u64 = if mainsection.contains_key("purge_after_withdraws") {
            match mainsection["purge_after_withdraws"] {
                None => {
                    return Err(ErrorConfig::from_str(
                        "invalid purge_after_withdraws was specified",
                    ));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid purge_after_withdraws - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            0
        };
        let purge_every: chrono::Duration = if mainsection.contains_key("purge_every") {
            match mainsection["purge_every"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid purge_every was specified"));
                }
                Some(ref s) => chrono::Duration::seconds(match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!(
                            "Invalid purge_every - {}",
                            e
                        )));
                    }
                    Ok(a) => a,
                }),
            }
        } else {
            chrono::Duration::minutes(5)
        };
        let whoisreqtimeout: u64 = if mainsection.contains_key("whois_request_timeout") {
            match mainsection["whois_request_timeout"] {
                Some(ref s) => s.parse().unwrap_or(30),
                None => 30,
            }
        } else {
            30
        };
        let whoiscachesecs: i64 = if mainsection.contains_key("whois_cache_seconds") {
            match mainsection["whois_cache_seconds"] {
                Some(ref s) => s.parse().unwrap_or(1800),
                None => 1800,
            }
        } else {
            1800
        };
        let whois: WhoIs = if mainsection.contains_key("whoisjsonconfig") {
            match mainsection["whoisjsonconfig"] {
                Some(ref s) => WhoIs::from_path(s).unwrap(),
                None => {
                    return Err(ErrorConfig::from_str("Invalid whoisjsonconfig"));
                }
            }
        } else {
            return Err(ErrorConfig::from_str("Invalid whoisjsonconfig"));
        };
        let whoisdb: String = if mainsection.contains_key("whoisdb") {
            match mainsection["whoisdb"] {
                Some(ref s) => s.to_string(),
                None => {
                    return Err(ErrorConfig::from_str("Invalid whoisdb"));
                }
            }
        } else {
            "whoiscache.db".to_string()
        };
        let mut dnses = Vec::<std::net::SocketAddr>::new();
        if mainsection.contains_key("whoisdns") {
            match mainsection["whoisdns"] {
                Some(ref s) => {
                    for sdns in s.as_str().split(',') {
                        match sdns.trim().parse() {
                            Ok(sck) => dnses.push(sck),
                            Err(_) => match (sdns.trim().to_string() + ":53").parse() {
                                Ok(sck) => dnses.push(sck),
                                Err(_) => {
                                    eprintln!("Invalid DNS: {}", sdns);
                                }
                            },
                        }
                    }
                }
                None => {
                    return Err(ErrorConfig::from_str("Invalid whoisdns"));
                }
            }
        };
        if dnses.is_empty() {
            dnses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
        };
        Ok(SvcConfig {
            httplisten: httplisten,
            httptimeout: httptimeout,
            httproot: httproot,
            historydepth: historydepth,
            historymode: historymode,
            whoisconfig: whois,
            whoisdb: whoisdb,
            whoisdnses: dnses,
            whoisreqtimeout: whoisreqtimeout,
            whoiscachesecs: whoiscachesecs,
            purge_after_withdraws: purge_after_withdraws,
            purge_every: purge_every,
            peers: peers,
        })
    }
}
