use crate::error::*;
use crate::scan::*;
use crate::serviceprobes::*;
use base64::encode;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

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
