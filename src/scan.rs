use base64::{decode, encode};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{error::Elapsed, timeout};
use tokio_native_tls::TlsConnector;
use tracing::{info, instrument};

use crate::serviceprobes::*;
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

#[derive(Debug, Clone, Serialize)]
pub struct RadarResult {
    pub target: Target,
    pub timestamp: u64,
    pub tls: Option<bool>,
    pub tls_response: Option<String>,
    pub tls_service_match: Option<Match>,
    pub response: Option<String>,
    pub service_match: Option<Match>,
    pub error: Option<String>,
    pub error_with_tls: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub tcp: bool,
    pub udp: bool,
    pub max_concurrent_scans: usize,
}

pub async fn start_scan<S>(
    targets: S,
    probes: ServiceProbes,
    tx: mpsc::Sender<RadarResult>,
    config: ScanConfig,
) where
    S: futures::Stream<Item = Target>,
{
    let cx = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_sni(false)
        .build()
        .expect("failed to build tls connector");
    let cx = tokio_native_tls::TlsConnector::from(cx);

    let detections = targets
        .map(|target| async { scan(target, &probes, &cx).await })
        .buffered(config.max_concurrent_scans);

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
    Tls(native_tls::Error),
}

impl fmt::Display for RadarScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RadarScanError::Io(ref err) => err.fmt(f),
            RadarScanError::Elapsed(ref err) => err.fmt(f),
            RadarScanError::Tls(ref err) => err.fmt(f),
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

impl From<native_tls::Error> for RadarScanError {
    fn from(err: native_tls::Error) -> RadarScanError {
        RadarScanError::Tls(err)
    }
}

pub async fn scan(
    target: Target,
    service_probes: &ServiceProbes,
    tls_connector: &TlsConnector,
) -> RadarResult {
    match run_scan(&target, service_probes, false, tls_connector).await {
        Ok(detection) => {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before unix epoch")
                .as_secs();
            if detection.service_match.service.starts_with("ssl") {
                match run_scan(&target, service_probes, false, tls_connector).await {
                    Ok(detection_with_tls) => RadarResult {
                        target,
                        timestamp,
                        tls: Some(true),
                        tls_response: Some(detection.response),
                        tls_service_match: Some(detection.service_match),
                        service_match: Some(detection_with_tls.service_match),
                        response: Some(detection_with_tls.response),
                        error: None,
                        error_with_tls: None,
                    },
                    Err(e) => RadarResult {
                        target,
                        timestamp,
                        tls: Some(true),
                        tls_response: Some(detection.response),
                        tls_service_match: Some(detection.service_match),
                        service_match: None,
                        response: None,
                        error: None,
                        error_with_tls: Some(e.to_string()),
                    },
                }
            } else {
                RadarResult {
                    target,
                    timestamp,
                    tls: Some(true),
                    tls_response: Some(detection.response),
                    tls_service_match: Some(detection.service_match),
                    service_match: None,
                    response: None,
                    error: None,
                    error_with_tls: None,
                }
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
                tls: None,
                tls_response: None,
                tls_service_match: None,
                service_match: None,
                response: None,
                error: Some(e.to_string()),
                error_with_tls: None,
            }
        }
    }
}

const TIMEOUT: u64 = 5;

struct Detection {
    response: String,
    service_match: Match,
}

#[instrument]
async fn run_scan(
    target: &Target,
    service_probes: &ServiceProbes,
    tls: bool,
    tls_connector: &TlsConnector,
) -> Result<Detection, RadarScanError> {
    let mut buf = vec![0u8; 1600];
    for probe in &service_probes.tcp_probes {
        let host = format!("{}:{}", target.ip, target.port);
        info!("attempting to connect to host {}", host);
        let mut stream = timeout(Duration::from_secs(TIMEOUT), async {
            TcpStream::connect(&host).await
        })
        .await??;
        info!("successfully connected to host {}", host);

        if tls {
            info!("attempting to negotiate tls connection with host {}", host);
            let mut stream = tls_connector.connect(&target.ip, stream).await?;
            info!("successfully negotiated tls connection with host {}", host);
            match run_service_probe(&host, &mut stream, &mut buf, &probe).await {
                Ok(detection) => return Ok(detection),
                Err(e) => info!("{:?}", e),
            }
        } else {
            match run_service_probe(&host, &mut stream, &mut buf, &probe).await {
                Ok(detection) => return Ok(detection),
                Err(e) => info!("{:?}", e),
            }
        }
    }

    Err(RadarScanError::NoDetection)
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncReadWrite for T {}

async fn run_service_probe<S>(
    host: &str,
    stream: &mut S,
    mut buf: &mut [u8],
    service_probe: &ServiceProbe,
) -> Result<Detection, RadarScanError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let request = &service_probe.probe.data;
    if request.len() > 0 {
        info!("writing to host {}", host);
        stream.write_all(&request.as_bytes()).await?;
        info!("finished writing to host {}", host);
    }

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

    let response = std::str::from_utf8(buf).expect("failed to decode response to utf8");
    let _ = stream.shutdown();
    match service_probe.check_match(response) {
        Some(service_match) => Ok(Detection {
            response: response.into(),
            service_match,
        }),
        None => Err(RadarScanError::NoDetection),
    }
}
