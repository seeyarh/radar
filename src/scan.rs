use base64::{decode, encode};
use futures::stream::StreamExt;
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{error::Elapsed, timeout};
use tracing::{info, instrument};

use crate::parseprobes::*;
use std::fmt;
use std::marker::Unpin;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Target {
    pub ip: String,
    pub domain: Option<String>,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarResult {
    pub target: Target,
    pub timestamp: u64,
    pub service: Option<String>,
    pub response: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    tcp: bool,
    udp: bool,
    max_concurrent_scans: usize,
}

pub async fn start_scan<S>(
    targets: S,
    probes: ServiceProbes,
    tx: mpsc::Sender<RadarResult>,
    config: ScanConfig,
) where
    S: futures::Stream<Item = Target>,
{
    let detections = targets
        .map(|target| async { scan(target, &probes).await })
        .buffered(max_concurrent_scans);

    detections
        .for_each(|d| async {
            tx.send(d).await.expect("failed to send");
        })
        .await;
}

#[derive(Debug)]
pub enum RadarScanError {
    Io(io::Error),
    Elapsed(Elapsed),
    NoDetection,
}

impl fmt::Display for RadarScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RadarScanError::Io(ref err) => err.fmt(f),
            RadarScanError::Elapsed(ref err) => err.fmt(f),
            RadarScanError::NoDetection => write!(f, "No Detection"),
        }
    }
}

impl From<io::Error> for RadarScanError {
    fn from(err: io::Error) -> RadarScanError {
        RadarScanError::Io(err)
    }
}

impl From<Elapsed> for RadarScanError {
    fn from(err: Elapsed) -> RadarScanError {
        RadarScanError::Elapsed(err)
    }
}

pub async fn scan(target: Target, service_probes: &ServiceProbes) -> RadarResult {
    match run_scan(&target, service_probes).await {
        Ok(detection) => {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before unix epoch")
                .as_secs();
            RadarResult {
                target,
                timestamp,
                service: Some(detection.service),
                response: Some(detection.response),
                error: None,
            }
        }
        Err(e) => {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before unix epoch")
                .as_secs();
            RadarResult {
                target,
                timestamp,
                service: None,
                response: None,
                error: Some(e.to_string()),
            }
        }
    }
}

const TIMEOUT: u64 = 5;

struct Detection {
    service: String,
    response: String,
}

#[instrument]
async fn run_scan(
    target: &Target,
    service_probes: &ServiceProbes,
) -> Result<Detection, RadarScanError> {
    let mut tls = true;
    let mut buf = vec![0u8; 1600];
    for probe in probes {
        let host = format!("{}:{}", target.ip, target.port);
        info!("attempting to connect to host {}", host);
        let mut stream = timeout(Duration::from_secs(TIMEOUT), async {
            TcpStream::connect(&host).await
        })
        .await??;
        info!("successfully connected to host {}", host);

        if tls {
            let (mut stream, use_tls) = try_tls(&host, &target.ip, stream).await?;
            tls = use_tls;

            match run_probe(&host, &mut stream, &mut buf, probe).await {
                Ok(detection) => return Ok(detection),
                Err(e) => info!("{:?}", e),
            }
        } else {
            match run_probe(&host, &mut stream, &mut buf, probe).await {
                Ok(detection) => return Ok(detection),
                Err(e) => info!("{:?}", e),
            }
        }
    }

    Err(RadarScanError::NoDetection)
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncReadWrite for T {}

async fn try_tls(
    host: &str,
    domain: &str,
    stream: TcpStream,
) -> Result<(Box<dyn AsyncReadWrite>, bool), RadarScanError> {
    info!("attempting to negotiate tls connection with host {}", host);
    let cx = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_sni(false)
        .build()
        .expect("failed to build tls connector");
    let cx = tokio_native_tls::TlsConnector::from(cx);
    match cx.connect(&domain, stream).await {
        Ok(s) => {
            info!("successfully negotiated tls connection with host {}", host);
            Ok((Box::new(s), true))
        }
        Err(e) => {
            info!("Error {} during tls negotiation with host {}", e, host);
            let s = timeout(Duration::from_secs(TIMEOUT), async {
                TcpStream::connect(&host).await
            })
            .await??;
            Ok((Box::new(s), false))
        }
    }
}

async fn run_service_probe<S>(
    host: &str,
    stream: &mut S,
    mut buf: &mut [u8],
    service_probe: &ServiceProbe,
) -> Result<Detection, RadarScanError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let request = decode(&probe.request).expect("failed to decode request b64");
    info!("writing to host {}", host);
    stream.write_all(&request).await?;
    info!("finished writing to host {}", host);

    info!("reading from host {}", host);
    let bytes_read = timeout(Duration::from_secs(TIMEOUT), async {
        stream.read(&mut buf).await
    })
    .await??;
    info!(
        "finished reading from host {}, {:?}",
        host,
        &buf[..bytes_read]
    );

    let response = decode(&probe.response).expect("failed to decode response b64");
    info!(
        "response to match {}",
        String::from_utf8(response.clone()).unwrap()
    );
    info!(
        "response recvd {}",
        String::from_utf8(buf[..bytes_read].to_vec()).unwrap()
    );
    if buf[..response.len()] == response {
        return Ok(Detection {
            service: probe.service.clone(),
            response: encode(response),
        });
    }

    // ignore the result
    let _ = stream.shutdown();
    Err(RadarScanError::NoDetection)
}
