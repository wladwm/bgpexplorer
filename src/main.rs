extern crate async_trait;
extern crate futures;
extern crate futures_util;
extern crate hyper;
extern crate tokio;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate ini;
extern crate url;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use tokio::fs::File;
use tokio::*;
use tokio_util::codec::{BytesCodec, FramedRead};

mod bgppeer;
mod bgprib;
mod bmppeer;
mod service;
use service::*;
mod bgpsvc;
use bgpsvc::*;
mod whoissvc;
use whoissvc::*;
mod config;
mod ribfilter;
mod ribservice;
mod tojson;
use config::*;

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
    pub whois: Arc<WhoisSvr>,
}
impl Clone for Svc {
    fn clone(&self) -> Svc {
        Svc {
            httproot: self.httproot.clone(),
            bgp: self.bgp.clone(),
            whois: self.whois.clone(),
        }
    }
}
impl Svc {
    pub fn new(http_root: Arc<String>, b: Arc<BgpSvr>, w: Arc<WhoisSvr>) -> Svc {
        Svc {
            httproot: http_root,
            bgp: Some(b),
            whois: w,
        }
    }
    pub async fn response_fn(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        if req.method() != Method::GET {
            return Ok(not_found());
        }
        let requri = req.uri().path();
        if requri.len() > 5 {
            if requri[..5] == "/api/"[..5] {
                let urlparts: Vec<&str> = requri.split('/').collect();
                if urlparts.len() > 2 {
                    match urlparts[2] {
                        "whois" => {
                            return self.whois.response_fn(&req).await;
                        }
                        "dns" => {
                            return self.whois.response_fn(&req).await;
                        }
                        "ping" => {
                            return Ok(Response::new(Body::from("pong")));
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
        }
        let filepath = String::new()
            + self.httproot.as_str()
            + (match requri {
                "/" => "/index.html",
                s => s,
            });
        //println!("File {}",filepath);
        simple_file_send(filepath.as_str()).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conf = match SvcConfig::from_inifile("bgpexplorer.ini") {
        Ok(sc) => sc,
        Err(e) => {
            eprintln!("{}", e);
            return Ok(());
        }
    };

    let token = tokio_util::sync::CancellationToken::new();
    let mut svr = BgpSvr::new(
        conf.clone(),
        token.clone(),
        conf.historydepth,
        conf.purge_after_withdraws,
    );
    svr.start_updates().await;
    let msvr = Arc::new(svr);
    let svc = Svc::new(
        Arc::new(conf.httproot),
        msvr.clone(),
        Arc::new(WhoisSvr::new(
            conf.whoisconfig,
            conf.whoisdb.clone(),
            conf.whoisdnses,
        )),
    );

    let tck1 = {
        let mut _svr = msvr.clone();
        let pmode = conf.peermode.clone();
        tokio::spawn(async move {
            _svr.run(pmode).await;
        })
    };
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
        println!("Listening on http://{}", conf.httplisten);
        if let Err(e) = Server::bind(&conf.httplisten).serve(service).await {
            eprintln!("server error: {}", e);
        }
        token.cancel();
    };
    tck1.await.unwrap();
    Ok(())
}
