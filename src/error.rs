use std::fmt;
use std::io;
use tokio::time::error::Elapsed;

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
