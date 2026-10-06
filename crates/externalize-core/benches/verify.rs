//! Cost of verification on real mainnet data.

#![allow(clippy::unwrap_used, missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use externalize_core::{Bundle, TrustSet};

const BUNDLE: &str = include_str!("../tests/fixtures/mainnet/bundle-64791359.json");

fn bench(c: &mut Criterion) {
    let trust = TrustSet::from_toml(include_str!("../../../trust/public.toml")).unwrap();
    let bundle = Bundle::from_json(BUNDLE).unwrap();
    let cert = externalize_core::Certificate { header: bundle.ledger.0.clone(), scp: bundle.scp.0.clone() };

    c.bench_function("parse bundle (111 KB JSON)", |b| b.iter(|| Bundle::from_json(BUNDLE).unwrap()));
    c.bench_function("certify ledger (30 signatures)", |b| b.iter(|| cert.verify(&trust).unwrap()));
    c.bench_function("verify bundle (certificate + 2 claims)", |b| b.iter(|| bundle.verify(&trust).unwrap()));
}

criterion_group!(benches, bench);
criterion_main!(benches);
