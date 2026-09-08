//! Throughput and latency benchmarks for `pq-objectstore`.
//!
//! ```bash
//! cargo run --release --example bench
//! ```

use std::time::{Duration, Instant};

use pq_objectstore::PqObjectStore;
use pq_objectstore::backend::MemoryBackend;
use pq_objectstore::crypto::{encapsulate, generate_keypair};
use pq_objectstore::key::{KeyId, KeyProvider, LocalKeyProvider};

fn fmt_bytes(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

fn fmt_rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(1e-12);
    format!("{}/s", fmt_bytes(bytes as f64 / secs))
}

fn fmt_duration(d: Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{:.3} s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{:.3} ms", d.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.1} µs", d.as_secs_f64() * 1_000_000.0)
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn make_store() -> pq_objectstore::Result<PqObjectStore> {
    let key_id = KeyId::new("bench-v1")?;
    let keys = LocalKeyProvider::generate(key_id.clone())?;
    PqObjectStore::builder()
        .backend(MemoryBackend::new())
        .key_provider(keys)
        .key_id_validated(key_id)
        .build()
}

async fn bench_put_get(size: usize, rounds: usize) -> pq_objectstore::Result<(Duration, Duration)> {
    let store = make_store().await?;
    let payload = vec![0xA5u8; size];
    let key = format!("bench/{size}");

    // Warmup
    store.put_bytes(&key, &payload).await?;
    let _ = store.get_bytes(&key).await?;

    let mut put_total = Duration::ZERO;
    let mut get_total = Duration::ZERO;
    for i in 0..rounds {
        let object_key = format!("{key}/{i}");
        let t0 = Instant::now();
        store.put_bytes(&object_key, &payload).await?;
        put_total += t0.elapsed();

        let t1 = Instant::now();
        let out = store.get_bytes(&object_key).await?;
        get_total += t1.elapsed();
        assert_eq!(out.len(), size);
    }

    Ok((put_total / rounds as u32, get_total / rounds as u32))
}

async fn bench_small_object_latency(
    rounds: usize,
) -> pq_objectstore::Result<(Duration, Duration, Duration)> {
    let store = make_store().await?;
    let payload = b"agent-memory-frame";
    let mut puts = Vec::with_capacity(rounds);
    let mut gets = Vec::with_capacity(rounds);
    let mut rts = Vec::with_capacity(rounds);

    for i in 0..rounds {
        let key = format!("latency/{i}");
        let t0 = Instant::now();
        store.put_bytes(&key, payload).await?;
        let put = t0.elapsed();

        let t1 = Instant::now();
        let out = store.get_bytes(&key).await?;
        let get = t1.elapsed();
        assert_eq!(out, payload);

        puts.push(put);
        gets.push(get);
        rts.push(put + get);
    }

    puts.sort();
    gets.sort();
    rts.sort();
    Ok((
        percentile(&puts, 0.50),
        percentile(&gets, 0.50),
        percentile(&rts, 0.50),
    ))
}

async fn bench_kem(rounds: usize) -> pq_objectstore::Result<(Duration, Duration)> {
    let key_id = KeyId::new("kem-bench")?;
    let keys = LocalKeyProvider::generate(key_id.clone())?;
    let pk = keys.public_key(&key_id).await?;

    // Warmup
    let (ct, _) = encapsulate(&pk)?;
    let _ = keys.decapsulate(&key_id, &ct).await?;

    let mut enc_total = Duration::ZERO;
    let mut dec_total = Duration::ZERO;
    for _ in 0..rounds {
        let t0 = Instant::now();
        let (ct, _) = encapsulate(&pk)?;
        enc_total += t0.elapsed();

        let t1 = Instant::now();
        let _ = keys.decapsulate(&key_id, &ct).await?;
        dec_total += t1.elapsed();
    }

    Ok((enc_total / rounds as u32, dec_total / rounds as u32))
}

fn bench_keypair(rounds: usize) -> Duration {
    // Warmup
    let _ = generate_keypair();
    let mut total = Duration::ZERO;
    for _ in 0..rounds {
        let t0 = Instant::now();
        let _ = generate_keypair();
        total += t0.elapsed();
    }
    total / rounds as u32
}

#[tokio::main]
async fn main() -> pq_objectstore::Result<()> {
    println!("pq-objectstore benchmark");
    println!("========================");
    println!();
    println!("suite: ML-KEM-768 + AES-256-GCM STREAM");
    println!("backend: MemoryBackend (crypto + framing only, no network)");
    println!();

    let kem_rounds = 200;
    let (enc, dec) = bench_kem(kem_rounds).await?;
    let keygen = bench_keypair(50);
    println!("## ML-KEM-768");
    println!();
    println!("| Operation        | Mean latency          | Samples |");
    println!("| ---------------- | --------------------- | ------- |");
    println!(
        "| Key generation   | {:>21} | {:>7} |",
        fmt_duration(keygen),
        50
    );
    println!(
        "| Encapsulation    | {:>21} | {kem_rounds:>7} |",
        fmt_duration(enc)
    );
    println!(
        "| Decapsulation    | {:>21} | {kem_rounds:>7} |",
        fmt_duration(dec)
    );
    println!();

    let (put_p50, get_p50, rt_p50) = bench_small_object_latency(200).await?;
    println!("## Small-object latency (18-byte payload)");
    println!();
    println!("| Path        | p50        |");
    println!("| ----------- | ---------- |");
    println!("| put         | {:>10} |", fmt_duration(put_p50));
    println!("| get         | {:>10} |", fmt_duration(get_p50));
    println!("| put + get   | {:>10} |", fmt_duration(rt_p50));
    println!();

    println!("## Streaming throughput");
    println!();
    println!("| Size   | put            | get            | rounds |");
    println!("| ------ | -------------- | -------------- | ------ |");

    let cases: &[(usize, usize)] = &[
        (1024, 100),
        (64 * 1024, 80),
        (1024 * 1024, 40),
        (10 * 1024 * 1024, 12),
        (100 * 1024 * 1024, 4),
    ];

    for &(size, rounds) in cases {
        let (put_avg, get_avg) = bench_put_get(size, rounds).await?;
        let put_rate = fmt_rate(size as u64, put_avg);
        let get_rate = fmt_rate(size as u64, get_avg);
        println!(
            "| {:>6} | {:>14} | {:>14} | {rounds:>6} |",
            fmt_bytes(size as f64),
            put_rate,
            get_rate,
        );
    }

    println!();
    println!("Notes:");
    println!("- Times include ML-KEM wrap/unwrap, AES-GCM STREAM, and PQOS framing.");
    println!("- Network / S3 upload latency is excluded (in-memory backend).");
    Ok(())
}
