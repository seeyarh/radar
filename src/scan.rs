use base64::encode;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;
use tracing::{info, instrument};

use crate::error::*;
use crate::output::*;
use crate::serviceprobes::*;
use std::marker::Unpin;
use std::time::Duration;

const TIMEOUT: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Target {
    pub ip: String,
    pub domain: Option<String>,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub tcp: bool,
    pub udp: bool,
    pub max_concurrent_scans: usize,
}

pub enum Detection {
    DetectionWithoutTls(DetectionInner),
    DetectionWithTls(DetectionWithTls),
}

pub struct DetectionInner {
    pub response: String,
    pub service_match: Match,
}

pub struct DetectionWithTls {
    pub detection: DetectionInner,
    pub tls_wrapped_result: Result<DetectionInner, RadarError>,
}

pub async fn start_scan<S>(
    targets: S,
    probes: ServiceProbes,
    tx: mpsc::Sender<RadarOutput>,
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

pub async fn scan(
    target: Target,
    service_probes: &ServiceProbes,
    tls_connector: &TlsConnector,
) -> RadarOutput {
    match run_scan(&target, service_probes, false, tls_connector).await {
        Ok(detection) => {
            if detection.service_match.service.starts_with("ssl") {
                let tls_wrapped_result =
                    run_scan(&target, service_probes, true, tls_connector).await;

                (
                    target,
                    Ok(Detection::DetectionWithTls(DetectionWithTls {
                        detection,
                        tls_wrapped_result,
                    })),
                )
                    .into()
            } else {
                (target, Ok(Detection::DetectionWithoutTls(detection))).into()
            }
        }
        Err(e) => (target, Err(e)).into(),
    }
}

trait AsyncReadWrite: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt + Unpin {}
impl<T: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt + Unpin> AsyncReadWrite for T {}

#[instrument(skip(service_probes, tls_connector))]
async fn run_scan(
    target: &Target,
    service_probes: &ServiceProbes,
    tls: bool,
    tls_connector: &TlsConnector,
) -> Result<DetectionInner, RadarError> {
    let mut buf = vec![0u8; 1600];
    // If we receive any data at any point, we want to return it, rather than an io error
    let prev_response: Option<Vec<u8>> = None;
    for probe in &service_probes.tcp_probes {
        let host = format!("{}:{}", target.ip, target.port);
        info!("attempting to connect");
        let mut stream = connect_with_timeout(&host).await.map_err(|e| {
            if prev_response.is_some() {
                info!(
                    "error connecting to host {}, previous probe returned data",
                    e.to_string()
                );
                RadarError::NoDetection(prev_response.clone().unwrap())
            } else {
                e
            }
        })?;
        info!("successfully connected");

        let r = if tls {
            info!("attempting to negotiate tls");
            let mut stream = tls_connector.connect(&target.ip, stream).await?;
            info!("successfully negotiated tls");
            run_service_probe_and_match(&mut stream, &mut buf, &probe).await
        } else {
            run_service_probe_and_match(&mut stream, &mut buf, &probe).await
        };

        match r {
            Ok(d) => return Ok(d),
            Err(RadarError::NoDetection(r)) => {
                info!("no match found for given probe, attempting fallback");
            }
            Err(RadarError::Elapsed(e)) => {
                if probe.probe.name != "NULL" {
                    return Err(RadarError::Elapsed(e));
                }
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!();
}

async fn connect_with_timeout(host: &str) -> Result<TcpStream, RadarError> {
    let stream = timeout(Duration::from_secs(TIMEOUT), async {
        TcpStream::connect(&host).await
    })
    .await?;
    stream.map_err(|e| e.into())
}

#[instrument(skip_all, fields(probe.name = service_probe.probe.name))]
async fn run_service_probe_and_match<S>(
    stream: &mut S,
    buf: &mut [u8],
    service_probe: &ServiceProbe,
) -> Result<DetectionInner, RadarError>
where
    S: AsyncReadWrite,
{
    let bytes_read = run_service_probe(stream, buf, service_probe).await?;
    let response = &buf[..bytes_read];

    info!("checking for matches");
    match service_probe.check_match(response) {
        Some(service_match) => {
            info!("found match");
            return Ok(DetectionInner {
                response: encode(&buf[..bytes_read]),
                service_match,
            });
        }
        None => {
            info!("no match");
            return Err(RadarError::NoDetection(response.into()));
        }
    }
}

#[instrument(skip_all, fields(probe.name = service_probe.probe.name))]
async fn run_service_probe<S>(
    stream: &mut S,
    mut buf: &mut [u8],
    service_probe: &ServiceProbe,
) -> Result<usize, RadarError>
where
    S: AsyncReadWrite,
{
    let request = &service_probe.probe.data;
    if request.len() > 0 {
        info!("writing");
        stream.write_all(&request).await?;
        info!("finished writing");
    }

    info!("reading");
    let bytes_read = timeout(Duration::from_secs(TIMEOUT), async {
        stream.read(&mut buf).await
    })
    .await??;
    info!("read {} bytes", bytes_read);

    let _ = stream.shutdown();
    Ok(bytes_read)
}
