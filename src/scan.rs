use base64::encode;
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
pub struct RadarOutput {
    pub target: Target,
    pub timestamp: u64,
    pub tls: Option<bool>,
    pub tls_response: Option<String>,
    pub tls_service_match: Option<Match>,
    pub response: Option<String>,
    pub service_match: Option<Match>,
    pub error: Option<String>,
    pub tls_error: Option<String>,
}

impl RadarOutput {
    fn new(target: Target, timestamp: u64) -> RadarOutput {
        RadarOutput {
            target,
            timestamp,
            tls: None,
            tls_response: None,
            tls_service_match: None,
            response: None,
            service_match: None,
            error: None,
            tls_error: None,
        }
    }
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

#[derive(Debug)]
pub enum RadarError {
    Io(io::Error),
    Elapsed(Elapsed),
    NoDetection(Vec<u8>),
    Tls(native_tls::Error),
}

impl fmt::Display for RadarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RadarError::Io(ref err) => err.fmt(f),
            RadarError::Elapsed(ref err) => err.fmt(f),
            RadarError::Tls(ref err) => err.fmt(f),
            RadarError::NoDetection(_) => write!(f, "No Detection"),
        }
    }
}

impl From<io::Error> for RadarError {
    fn from(err: io::Error) -> RadarError {
        RadarError::Io(err)
    }
}

impl From<Elapsed> for RadarError {
    fn from(err: Elapsed) -> RadarError {
        RadarError::Elapsed(err)
    }
}

impl From<native_tls::Error> for RadarError {
    fn from(err: native_tls::Error) -> RadarError {
        RadarError::Tls(err)
    }
}

enum Detection {
    DetectionWithoutTls(DetectionInner),
    DetectionWithTls(DetectionWithTls),
}

struct DetectionInner {
    response: String,
    service_match: Match,
}

struct DetectionWithTls {
    detection: DetectionInner,
    tls_wrapped_result: Result<DetectionInner, RadarError>,
}

impl RadarOutput {
    // successful detection of a tls service, and successful detection of the
    // tls wrapped service
    fn update_detection_with_tls(
        &mut self,
        detection: DetectionInner,
        tls_wrapped_detection: DetectionInner,
    ) {
        self.tls = Some(true);
        self.response = Some(detection.response);
        self.service_match = Some(detection.service_match);
        self.tls_response = Some(tls_wrapped_detection.response);
        self.tls_service_match = Some(tls_wrapped_detection.service_match);
    }

    // successful detection of a tls service, and error attempting to detect
    // tls wrapped service
    fn update_detection_with_tls_error(&mut self, detection: DetectionInner, e: RadarError) {
        self.tls = Some(true);
        // this will be some kind of tls response
        self.response = Some(detection.response);
        self.service_match = Some(detection.service_match);
        match e {
            RadarError::NoDetection(ref r) => self.tls_response = Some(encode(r)),
            _ => (),
        }
        self.tls_error = Some(e.to_string());
    }

    fn update_detection_without_tls(&mut self, d: DetectionInner) {
        self.tls = Some(false);
        self.response = Some(d.response);
        self.service_match = Some(d.service_match);
    }

    fn update_error(&mut self, e: RadarError) {
        self.tls = Some(false);
        match e {
            RadarError::NoDetection(ref r) => self.response = Some(encode(r)),
            _ => (),
        }
        self.error = Some(e.to_string());
    }
}

impl From<(Target, Result<Detection, RadarError>)> for RadarOutput {
    fn from(target_result: (Target, Result<Detection, RadarError>)) -> RadarOutput {
        let (target, r) = target_result;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before unix epoch")
            .as_secs();

        let mut output = RadarOutput::new(target, timestamp);

        match r {
            Ok(detection) => match detection {
                Detection::DetectionWithTls(detection) => match detection.tls_wrapped_result {
                    Ok(tls_wrapped_detection) => {
                        output.update_detection_with_tls(detection.detection, tls_wrapped_detection)
                    }
                    Err(e) => output.update_detection_with_tls_error(detection.detection, e),
                },
                Detection::DetectionWithoutTls(detection) => {
                    output.update_detection_without_tls(detection)
                }
            },
            Err(e) => output.update_error(e),
        }
        output
    }
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

const TIMEOUT: u64 = 5;

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
    for probe in &service_probes.tcp_probes {
        let host = format!("{}:{}", target.ip, target.port);
        info!("attempting to connect");
        let mut stream = timeout(Duration::from_secs(TIMEOUT), async {
            TcpStream::connect(&host).await
        })
        .await??;
        info!("successfully connected");

        if tls {
            info!("attempting to negotiate tls");
            let mut stream = tls_connector.connect(&target.ip, stream).await?;
            info!("successfully negotiated tls");
            match run_service_probe_and_match(&mut stream, &mut buf, &probe).await {
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
        } else {
            match run_service_probe_and_match(&mut stream, &mut buf, &probe).await {
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
    }
    unreachable!();
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
