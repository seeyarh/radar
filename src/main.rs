//! Radar protocol detector CLI
use futures::stream::StreamExt;

use clap::Parser;
use std::error::Error;
use std::time::Instant;

use tokio::fs::File;
use tokio::io::{self, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use radar::output::RadarOutput;
use radar::scan::{start_scan, ScanConfig, Target};
use radar::serviceprobes::parse::read_service_probes_file;

/// Run Radar Protocol Detector
#[derive(Debug, Clone, Parser)]
#[command(version = "0.0.1", author = "Collins Huff")]
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

    /// run tcp probes
    #[clap(short, long)]
    tcp: bool,

    /// run udp probes
    #[clap(short, long)]
    udp: bool,
}

impl Into<ScanConfig> for Opts {
    fn into(self) -> ScanConfig {
        ScanConfig {
            tcp: self.tcp,
            udp: self.udp,
            max_concurrent_scans: self.max_concurrent_scans,
        }
    }
}

const MAX_BUFFERED_RESULTS: usize = 10000;
async fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let service_probes = read_service_probes_file(&opts.probes_file);
    tracing::info!("loaded service probes in {}", start.elapsed().as_secs_f64());

    let f = io::stdin();

    let mut rdr = csv_async::AsyncReaderBuilder::new()
        .has_headers(false)
        .create_deserializer(f);

    let f = &opts.out_file.as_ref().unwrap();
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

    start_scan(targets, service_probes, tx, opts.into()).await;
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
    mut rx: mpsc::Receiver<RadarOutput>,
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
