use std::error::Error;
use std::fmt;
use std::str::FromStr;
use whois_rust::WhoIs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMode {
    BgpActive,
    BgpPassive,
    BmpPassive,
    BmpActive,
}
#[derive(Debug, Clone)]
pub struct SvcConfig {
    pub routerid: std::net::Ipv4Addr,
    pub bgppeeras: u32,
    pub bgppeer: Option<std::net::SocketAddr>,
    pub protolisten: Option<std::net::SocketAddr>,
    pub bmppeer: Option<std::net::SocketAddr>,
    pub httplisten: std::net::SocketAddr,
    pub httproot: String,
    pub historydepth: usize,
    pub whoisconfig: WhoIs,
    pub whoisdb: String,
    pub whoisdnses: Vec<std::net::SocketAddr>,
    pub peermode: PeerMode,
    pub purge_after_withdraws: u64,
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

impl SvcConfig {
    pub fn from_inifile(inifile: &str) -> Result<SvcConfig, ErrorConfig> {
        let conf = ini!(inifile);
        if !conf.contains_key("main") {
            return Err(ErrorConfig::from_str("Missing section 'main' in ini file"));
        }
        let mainsection = &conf["main"];
        if !mainsection.contains_key("session") {
            return Err(ErrorConfig::from_string(format!(
                "Missing value 'session' in [main] section ini file {}",
                inifile
            )));
        };
        let session = match mainsection["session"] {
            None => {
                return Err(ErrorConfig::from_str("No session specified"));
            }
            Some(ref s) => s,
        };
        if !conf.contains_key(session) {
            return Err(ErrorConfig::from_string(format!(
                "Missing section '{}' in ini file",
                session
            )));
        };
        let svcsection = &conf[session];

        let mode = match svcsection["mode"] {
            None => {
                return Err(ErrorConfig::from_str(
                    "No mode (bgpactive|bgppassive|bmpactive|bmppassive) specified",
                ));
            }
            Some(ref s) => s,
        };
        let peermode = mode.parse()?;
        let bgppeer: Option<std::net::SocketAddr> = if svcsection.contains_key("bgppeer") {
            match svcsection["bgppeer"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid bgppeer was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(_e) => {
                        let peerip: std::net::IpAddr = match s.parse() {
                            Err(_) => {
                                return Err(ErrorConfig::from_str("invalid bgppeer was specified"));
                            }
                            Ok(v) => v,
                        };
                        Some(std::net::SocketAddr::new(peerip, 179))
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            if peermode == PeerMode::BgpActive {
                // fatal error
                return Err(ErrorConfig::from_str("bgppeer was not specified"));
            } else {
                None
            }
        };
        let bmppeer: Option<std::net::SocketAddr> = if svcsection.contains_key("bmppeer") {
            match svcsection["bmppeer"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid bmppeer was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(_e) => {
                        let peerip: std::net::IpAddr = match s.parse() {
                            Err(_) => {
                                return Err(ErrorConfig::from_str("invalid bmppeer was specified"));
                            }
                            Ok(v) => v,
                        };
                        Some(std::net::SocketAddr::new(peerip, 632))
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            if peermode == PeerMode::BmpActive {
                // fatal error
                return Err(ErrorConfig::from_str("bmppeer was not specified"));
            } else {
                None
            }
        };
        let protolisten: Option<std::net::SocketAddr> = if svcsection.contains_key("protolisten") {
            match svcsection["protolisten"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid protolisten was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(_) => {
                        let lip: std::net::IpAddr = match s.parse() {
                            Err(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                            Ok(v) => v,
                        };
                        Some(std::net::SocketAddr::new(lip, 179))
                    }
                    Ok(a) => Some(a),
                },
            }
        } else {
            if peermode == PeerMode::BmpPassive || peermode == PeerMode::BgpPassive {
                return Err(ErrorConfig::from_str("protolisten was not specified"));
            } else {
                None
            }
        };
        let routerid: std::net::Ipv4Addr = if svcsection.contains_key("routerid") {
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
            match "1.1.1.1".parse() {
                Err(e) => {
                    return Err(ErrorConfig::from_string(format!(
                        "Invalid routerid - {}",
                        e
                    )));
                }
                Ok(a) => a,
            }
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
        let purge_after_withdraws: u64 = if mainsection.contains_key("purge") {
            match mainsection["purge"] {
                None => {
                    return Err(ErrorConfig::from_str("invalid purge was specified"));
                }
                Some(ref s) => match s.parse() {
                    Err(e) => {
                        return Err(ErrorConfig::from_string(format!("Invalid purge - {}", e)));
                    }
                    Ok(a) => a,
                },
            }
        } else {
            10000
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
            dnses.push("1.1.1.1:53".parse().unwrap());
        };
        Ok(SvcConfig {
            routerid: routerid,
            bgppeer: bgppeer,
            bmppeer: bmppeer,
            protolisten: protolisten,
            bgppeeras: bgppeeras,
            httplisten: httplisten,
            httproot: httproot,
            historydepth: historydepth,
            whoisconfig: whois,
            whoisdb: whoisdb,
            whoisdnses: dnses,
            peermode: peermode,
            purge_after_withdraws: purge_after_withdraws,
        })
    }
}
