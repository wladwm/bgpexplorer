extern crate async_trait;
extern crate futures;
extern crate futures_util;
extern crate hyper;
extern crate tokio;
extern crate websocket_codec;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate ini;
extern crate url;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;
#[macro_use]
extern crate anyhow;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

use futures::SinkExt;
use hyper::header::{self, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use websocket_codec::{ClientRequest, Message, MessageCodec};

use tokio::fs::File;
use tokio::*;
use tokio_util::codec::{BytesCodec, Decoder, Framed, FramedRead};

mod bgpattrs;
mod bgppeer;
mod bgprib;
use bgprib::*;
mod bmppeer;
mod service;
use service::*;
mod bgpsvc;
use bgpsvc::*;
#[cfg(feature = "whoisreq")]
mod whoissvc;
#[cfg(feature = "whoisreq")]
use whoissvc::*;
mod config;
use config::*;
mod ribfilter;
mod ribservice;
mod storage;
mod subscriber;
mod timestamp;

use std::sync::Arc;

static NOTFOUND: &[u8] = b"Not Found";

/// HTTP status code 404
fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(NOTFOUND.into())
        .unwrap()
}

async fn simple_file_send(filename: &str) -> Result<Response<Body>, hyper::Error> {
    if let Ok(file) = File::open(filename).await {
        let stream = FramedRead::new(file, BytesCodec::new());
        let body = Body::wrap_stream(stream);
        return Ok(Response::new(body));
    }
    Ok(not_found())
}

pub struct Svc {
    pub httproot: Arc<String>,
    pub bgp: Option<Arc<BgpSvr>>,
    #[cfg(feature = "whoisreq")]
    pub whois: Arc<WhoisSvr>,
}
impl Clone for Svc {
    fn clone(&self) -> Svc {
        Svc {
            httproot: self.httproot.clone(),
            bgp: self.bgp.clone(),
            #[cfg(feature = "whoisreq")]
            whois: self.whois.clone(),
        }
    }
}
impl Svc {
    pub fn new(
        http_root: Arc<String>,
        b: Arc<BgpSvr>,
        #[cfg(feature = "whoisreq")] w: Arc<WhoisSvr>,
    ) -> Svc {
        Svc {
            httproot: http_root,
            bgp: Some(b),
            #[cfg(feature = "whoisreq")]
            whois: w,
        }
    }
    pub async fn shutdown(&self) {
        if let Some(bgp) = self.bgp.as_ref() {
            bgp.shutdown().await;
        }
    }
    async fn on_client(&self, mut client: Framed<Upgraded, MessageCodec>) {
        if self.bgp.is_none() {
            let _ = client.send(Message::close(None)).await;
            return;
        }
        let rcv = self.bgp.as_ref().unwrap().subscribe_bgp().await;
        subscriber::on_subscriber_client(rcv, client).await;
    }
    async fn server_upgrade(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let mut res = Response::new(Body::empty());

        let ws_accept = if let Ok(req) = ClientRequest::parse(|name| {
            let h = req.headers().get(name)?;
            h.to_str().ok()
        }) {
            req.ws_accept()
        } else {
            *res.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(res);
        };
        let slf = self.clone();
        task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let client = MessageCodec::server().framed(upgraded);
                    slf.on_client(client).await;
                }
                Err(e) => error!("upgrade error: {}", e),
            }
        });

        *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

        let headers = res.headers_mut();
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&ws_accept).unwrap(),
        );
        Ok(res)
    }
    pub async fn response_fn(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        if req.method() != Method::GET {
            return Ok(not_found());
        }
        let requri = req.uri().path();
        if requri.len() > 5 && requri[..5] == "/api/"[..5] {
            let urlparts: Vec<&str> = requri.split('/').collect();
            if urlparts.len() > 2 {
                match urlparts[2] {
                    #[cfg(feature = "whoisreq")]
                    "whois" => {
                        return self.whois.response_fn(&req).await;
                    }
                    #[cfg(feature = "whoisreq")]
                    "dns" => {
                        return self.whois.response_fn(&req).await;
                    }
                    "ping" => {
                        return Ok(Response::new(Body::from("pong")));
                    }
                    "ws" => {
                        return self.server_upgrade(req).await;
                    }
                    _ => {
                        if let Some(bgpr) = &self.bgp {
                            return bgpr.response_fn(&req).await;
                        } else {
                            //panic!("No service")
                            return Ok(Response::new(Body::from("No service")));
                        }
                    }
                }
            }
        }
        let filepath = self.httproot.to_string()
            + (match requri {
                "/" => "/index.html",
                s => s,
            });
        simple_file_send(filepath.as_str()).await
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use storage::Storage;
    pretty_env_logger::init_timed();
    let fname = std::env::var("BGPEXPLORER").unwrap_or_else(|_| "bgpexplorer.ini".to_string());
    let conf = match SvcConfig::from_inifile(&fname) {
        Ok(sc) => Arc::new(sc),
        Err(e) => {
            error!("{}", e);
            return Ok(());
        }
    };
    let storage: Arc<dyn crate::storage::Storage + std::marker::Send + Sync> = match conf
        .storage
        .as_ref()
    {
        None => {
            let mut s = storage::NoStorage::default();
            s.open().await?;
            Arc::new(s)
        }
        Some(s) => {
            let pars = match s.split_once(":") {
                Some(p) => p,
                None => {
                    return Err(anyhow!("Unknown storage: {}", s));
                }
            };
            match pars.0 {
                "files" => {
                    let mut s = storage::textfile::TextWriter::new(pars.1.to_string());
                    s.open().await?;
                    Arc::new(s)
                }
                #[cfg(feature = "clickhouse")]
                "clickhouse" => {
                    let mut opts = klickhouse::ClientOptions::default();
                    let mut target = "127.0.0.1:9000".to_string();
                    let mut cso = storage::clickhouse::ClickhouseStorageOptions::default();
                    for p in pars.1.split(",") {
                        if let Some(v) = p.split_once("=") {
                            match v.0 {
                                "id" => cso.instance_id = v.1.to_string(),
                                "username" => opts.username = v.1.to_string(),
                                "password" => opts.password = v.1.to_string(),
                                "database" => opts.default_database = v.1.to_string(),
                                "partition_by" => cso.partition_by = v.1.to_string(),
                                "table_ttl" => cso.table_ttl = v.1.to_string(),
                                "connect" | "target" => target = v.1.to_string(),
                                "batch_size" => {
                                    cso.batch_size = v.1.parse().unwrap_or(cso.batch_size)
                                }
                                "batch_duration" => {
                                    cso.batch_dur = std::time::Duration::from_secs_f64(
                                        v.1.parse().unwrap_or(5f64),
                                    )
                                }
                                "break_count" => {
                                    cso.break_count = v.1.parse().unwrap_or(cso.break_count)
                                }
                                _ => {
                                    warn!("clickhouse unknown {}", p);
                                }
                            }
                        }
                    }
                    let mut s =
                        storage::clickhouse::ClickhouseStorage::new(target, opts, cso).await?;
                    s.open().await?;
                    Arc::new(s)
                }
                #[cfg(feature = "mysql")]
                "mysql" => {
                    let mut opts = mysql_async::OptsBuilder::from_opts(
                        mysql_async::Opts::from_url("mysql://localhost/bgp")?,
                    );
                    let mut instance: String = "".to_string();
                    for p in pars.1.split(",") {
                        if let Some(v) = p.split_once("=") {
                            match v.0 {
                                "id" => instance = v.1.to_string(),
                                "dburl" => {
                                    opts = mysql_async::OptsBuilder::from_opts(
                                        mysql_async::Opts::from_url(v.1)?,
                                    )
                                }
                                "password" => opts = opts.pass(Some(v.1)),
                                "database" => opts = opts.db_name(Some(v.1)),
                                "user" | "username" => opts = opts.user(Some(v.1)),
                                "host" | "connect" | "target" => opts = opts.ip_or_hostname(v.1),
                                _ => {
                                    warn!("mysql unknown {}", p);
                                }
                            }
                        }
                    }
                    opts = opts.setup(vec!["set NAMES utf8mb4", "SET CHARSET utf8mb4"]);
                    let pool = mysql_async::Pool::new(opts);
                    let mut s = storage::mysql::MysqlStorage::new(instance, pool).await?;
                    s.open().await?;
                    Arc::new(s)
                }
                _ => return Err(anyhow!("Unknown storage: {}", s)),
            }
        }
    };
    let token = tokio_util::sync::CancellationToken::new();
    let mut svr = BgpSvr::new(conf.clone(), storage.clone(), token.clone());
    svr.start_updates().await;
    let msvr = Arc::new(svr);
    let svc = Svc::new(
        Arc::new(conf.httproot.clone()),
        msvr.clone(),
        #[cfg(feature = "whoisreq")]
        Arc::new(WhoisSvr::new(&conf)),
    );

    let tck1 = {
        let mut _svr = msvr.clone();
        tokio::spawn(async move {
            _svr.run().await;
        })
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(10);
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::hangup())?;
        let txc = tx.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal HUP");
                let _ = txc.send(()).await;
            }
        });
    }
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::interrupt())?;
        let txc = tx.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal INT");
                let _ = txc.send(()).await;
            }
        });
    }
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::terminate())?;
        let txc = tx.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal TERM");
                let _ = txc.send(()).await;
            }
        });
    }
    #[cfg(windows)]
    {
        let txc = tx.clone();
        let mut stream = signal::windows::ctrl_break()?;
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_break");
                let _ = txc.send(()).await;
            }
        });
        let txc = tx.clone();
        let mut stream = signal::windows::ctrl_close()?;
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                let _ = txc.send(()).await;
            }
        });
        let txc = tx.clone();
        let mut stream = signal::windows::ctrl_logoff()?;
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                let _ = txc.send(()).await;
            }
        });
        let txc = tx.clone();
        let mut stream = signal::windows::ctrl_shutdown()?;
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                let _ = txc.send(()).await;
            }
        });
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = signal::ctrl_c().await {
                warn!("ctrl_c await error: {}", e);
            } else {
                info!("got ctrl_c signal");
                let _ = tx.send(()).await;
            }
        }
    });
    {
        //let mksvc = make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(response_fn)) });
        let _svc = svc.clone();
        let service = {
            make_service_fn(|_| {
                let _svc1 = _svc.clone();
                async move {
                    let _svc2 = _svc1.clone();
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let _svc3 = _svc2.clone();
                        async move { _svc3.response_fn(req).await }
                    }))
                }
            })
        };
        info!("Listening on http://{}", conf.httplisten);
        let server = Server::bind(&conf.httplisten).serve(service);
        let graceful = server.with_graceful_shutdown(async {
            let _ = rx.recv().await;
            info!("shutdown graceful");
        });

        if let Err(e) = graceful.await {
            error!("server error: {}", e);
        }
        info!("Server done: {}", conf.httplisten);
        token.cancel();
    };
    debug!("shutdown service");
    svc.shutdown().await;
    debug!("shutdown storage");
    if let Err(e) = storage.shutdown().await {
        error!("storage shutdown error: {}", e);
    }
    tck1.await.unwrap();
    Ok(())
}
