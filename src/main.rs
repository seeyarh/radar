//! Radar protocol detector CLI
use futures::stream::StreamExt;

use clap::Clap;

use std::error::Error;
use std::time::Instant;

use tokio::fs::{read_to_string, File};
use tokio::io::{self, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use radar::scan::{start_scan, Probe, RadarResult, Target};

/// Run Radar Protocol Detector
#[derive(Clap, Debug)]
#[clap(version = "1.0", author = "Collins Huff chuff@paloaltonetworks.com")]
struct Opts {
    /// Path to output file, defaults to stdout
    #[clap(short, long)]
    out_file: Option<String>,

    /// Path to log file, defaults to stderr
    #[clap(short, long)]
    log_file: Option<String>,

    /// Path to log file, defaults to stderr
    #[clap(short, long)]
    probes_file: String,

    /// Max concurrent scans
    #[clap(long, default_value = "50000")]
    max_concurrent_scans: usize,
}

async fn get_service_probes(probes_file: &str) -> Result<Vec<Probe>, Box<dyn Error>> {
    let s = read_to_string(probes_file).await?;
    let probes: Vec<Probe> = serde_yaml::from_str(&s)?;
    Ok(probes)
}

const MAX_BUFFERED_RESULTS: usize = 10000;
async fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let service_probes = get_service_probes(&opts.probes_file).await.expect("failed to get probes");
    tracing::info!("loaded probes: {:?}", service_probes);

    let start = Instant::now();

    let f = io::stdin();

    let mut rdr = csv_async::AsyncReaderBuilder::new()
        .has_headers(false)
        .create_deserializer(f);

    let f = opts.out_file.unwrap();
    let f = File::create(&f).await?;
    let writer = io::BufWriter::new(f);

    let (tx, rx) = mpsc::channel(MAX_BUFFERED_RESULTS);
    let writer_task = tokio::spawn(async move { write_results(writer, rx).await });

    let records = rdr.deserialize::<Target>();

    let targets = records.filter_map(|record| async move {
        match record {
            Ok(target) => Some(target),
            Err(e) => {
                tracing::warn!("failed to parse input {:?}", e);
                None
            }
        }
    });

    start_scan(targets, service_probes, tx, opts.max_concurrent_scans).await;
    let n_targets = writer_task.await??;

    let duration = start.elapsed();
    tracing::info!(
        "scanned {} targets in {} seconds",
        n_targets,
        duration.as_secs_f64()
    );

    Ok(())
}

async fn write_results<T>(
    mut writer: BufWriter<T>,
    mut rx: mpsc::Receiver<RadarResult>,
) -> io::Result<u64>
where
    T: AsyncWriteExt + Unpin,
{
    let mut n = 0;
    while let Some(result) = rx.recv().await {
        writer.write_all(&serde_json::to_vec(&result)?).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        n += 1;
    }
    Ok(n)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let opts: Opts = Opts::parse();
    run(opts).await.expect("fail");
}
