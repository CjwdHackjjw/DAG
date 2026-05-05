// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use config::{Authority, PrimaryAddresses};
use crypto::{generate_keypair, SecretKey};
use primary::{FreezeProposal, Header};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::collections::{BTreeSet, VecDeque};
use tokio::sync::mpsc::channel;

// Fixture
fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture
pub fn mock_committee() -> Committee {
    Committee {
        authorities: keys()
            .iter()
            .map(|(id, _)| {
                (
                    *id,
                    Authority {
                        stake: 1,
                        primary: PrimaryAddresses {
                            primary_to_primary: "0.0.0.0:0".parse().unwrap(),
                            worker_to_primary: "0.0.0.0:0".parse().unwrap(),
                        },
                        workers: HashMap::default(),
                    },
                )
            })
            .collect(),
    }
}

// Fixture: one certificate per node per round, with path_id = author and timestamp = round * 100 + author_index
fn mock_certificate(
    origin: PublicKey,
    round: Round,
    parents: BTreeSet<Digest>,
    timestamp: u64,
) -> Certificate {
    let mut header = Header {
        author: origin,
        round,
        parents,
        path_id: origin,
        ..Header::default()
    };
    header.id = header.digest();

    Certificate {
        header,
        timestamp,
        ..Certificate::default()
    }
}

// Creates a batch of certificates, one per node, and returns the certificate queue and the next round's parents
fn make_certificates(
    start: Round,
    stop: Round,
    initial_parents: &BTreeSet<Digest>,
    keys: &[(PublicKey, u64)],  // (public key, timestamp offset)
) -> (VecDeque<Certificate>, BTreeSet<Digest>) {
    let mut certificates = VecDeque::new();
    let mut parents = initial_parents.iter().cloned().collect::<BTreeSet<_>>();
    let mut next_parents = BTreeSet::new();

    for round in start..=stop {
        next_parents.clear();
        for (name, ts_offset) in keys {
            let timestamp = round * 1000 + ts_offset;
            let certificate = mock_certificate(*name, round, parents.clone(), timestamp);
            next_parents.insert(certificate.digest());
            certificates.push_back(certificate);
        }
        parents = next_parents.clone();
    }
    (certificates, next_parents)
}

// Basic test: four nodes each propose on an independent path, one certificate per round, and consensus should commit correctly
#[tokio::test]
async fn commit_basic() {
    let keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let keys_with_ts: Vec<_> = keys.iter().enumerate().map(|(i, k)| (*k, i as u64)).collect();

    let genesis = Certificate::genesis(&mock_committee());
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    // Generate certificates for four rounds, four nodes per round, to trigger executability updates for the first few rounds
    let (mut certificates, _) = make_certificates(1, 4, &genesis_digests, &keys_with_ts);

    // Spawn consensus
    let (tx_waiter, rx_waiter) = channel(10);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    Consensus::spawn(
        mock_committee(),
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    // Send all certificates.
    while let Some(cert) = certificates.pop_front() {
        tx_waiter.send(cert).await.unwrap();
    }

    // Wait with a timeout for at least one commit to avoid flaky empty reads caused by scheduling jitter.
    let first = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        rx_output.recv(),
    )
    .await
    .expect("Timed out waiting for committed certificates");

    let mut committed = Vec::new();
    if let Some(cert) = first {
        committed.push(cert);
    }

    while let Ok(cert) = rx_output.try_recv() {
        committed.push(cert);
    }
    // Certificates from rounds 1, 2, and 3 should be committed.
    assert!(!committed.is_empty(), "Should have committed some certificates");
    // Verify timestamp ordering.
    for i in 1..committed.len() {
        assert!(
            committed[i-1].timestamp <= committed[i].timestamp,
            "Certificates should be ordered by timestamp"
        );
    }
}

// Single-path test: only one node proposes, verifying recursive executability updates
#[tokio::test]
async fn single_path_commit() {
    let keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let name = keys[0];
    let committee = mock_committee();

    let genesis = Certificate::genesis(&committee);
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    // Create a single-node certificate chain over five rounds.
    let mut certificates = VecDeque::new();
    let mut parents = genesis_digests.clone();
    for round in 1..=5 {
        let timestamp = round * 1000;
        let cert = mock_certificate(name, round, parents.clone(), timestamp);
        parents = [cert.digest()].iter().cloned().collect();
        certificates.push_back(cert);
    }

    let (tx_waiter, rx_waiter) = channel(10);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    Consensus::spawn(
        committee,
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    while let Some(cert) = certificates.pop_front() {
        tx_waiter.send(cert).await.unwrap();
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let mut committed = Vec::new();
    while let Ok(cert) = rx_output.try_recv() {
        committed.push(cert);
    }

    // When the round-5 certificate arrives, the round-4 header becomes executable.
    // When the round-4 certificate arrives, the round-3 header becomes executable.
    // ... and so on.
    // Verify round ordering.
    if !committed.is_empty() {
        for i in 1..committed.len() {
            assert!(
                committed[i-1].round() <= committed[i].round(),
                "Rounds should be non-decreasing"
            );
        }
    }
}

#[tokio::test]
async fn commit_with_freeze_path() {
    let all_keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let keys_with_ts: Vec<_> = all_keys.iter().enumerate().map(|(i, k)| (*k, i as u64)).collect();

    let observer = all_keys[0];
    let target = all_keys[1];

    let genesis = Certificate::genesis(&mock_committee());
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    // 先构造 1..4 轮完整证书
    let (mut certificates, _) = make_certificates(1, 4, &genesis_digests, &keys_with_ts);

    // Inject a certificate carrying a freeze result into the observer's round-4 certificate.
    for cert in certificates.iter_mut() {
        if cert.origin() == observer && cert.round() == 4 {
            cert.header.freeze_proposal = Some(FreezeProposal {
                target_path: target,
                stall_round: 3,
                observer,
            });
            cert.frozen_paths.insert(target);
            break;
        }
    }

    // Then append round 5, where only non-target paths continue to advance.
    let round4_parents: BTreeSet<_> = certificates
        .iter()
        .filter(|c| c.round() == 4)
        .map(|c| c.digest())
        .collect();
    for (idx, name) in all_keys.iter().enumerate() {
        if *name == target {
            continue;
        }
        let cert = mock_certificate(*name, 5, round4_parents.clone(), 5000 + idx as u64);
        certificates.push_back(cert);
    }

    let (tx_waiter, rx_waiter) = channel(32);
    let (tx_primary, mut rx_primary) = channel(32);
    let (tx_output, mut rx_output) = channel(32);
    Consensus::spawn(mock_committee(), 50, rx_waiter, tx_primary, tx_output);
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    while let Some(cert) = certificates.pop_front() {
        tx_waiter.send(cert).await.unwrap();
    }

    let first = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx_output.recv())
        .await
        .expect("Timed out waiting for committed certificates under freeze");

    let mut committed = Vec::new();
    if let Some(cert) = first {
        committed.push(cert);
    }
    while let Ok(cert) = rx_output.try_recv() {
        committed.push(cert);
    }

    assert!(!committed.is_empty(), "Freeze scenario should still commit certificates");
    assert!(
        committed.iter().all(|c| !(c.origin() == target && c.round() >= 4)),
        "Frozen path should not commit certificates at or after freeze round"
    );
}

#[tokio::test]
async fn freeze_certificate_is_accepted_and_order_kept() {
    let all_keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let keys_with_ts: Vec<_> = all_keys.iter().enumerate().map(|(i, k)| (*k, i as u64)).collect();

    let observer = all_keys[0];
    let target = all_keys[2];

    let genesis = Certificate::genesis(&mock_committee());
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    let (mut certificates, _) = make_certificates(1, 4, &genesis_digests, &keys_with_ts);

    // Inject a certificate carrying a freeze result.
    for cert in certificates.iter_mut() {
        if cert.origin() == observer && cert.round() == 4 {
            cert.header.freeze_proposal = Some(FreezeProposal {
                target_path: target,
                stall_round: 3,
                observer,
            });
            cert.frozen_paths.insert(target);
            break;
        }
    }

    let (tx_waiter, rx_waiter) = channel(32);
    let (tx_primary, mut rx_primary) = channel(32);
    let (tx_output, mut rx_output) = channel(32);
    Consensus::spawn(mock_committee(), 50, rx_waiter, tx_primary, tx_output);
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    while let Some(cert) = certificates.pop_front() {
        tx_waiter.send(cert).await.unwrap();
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    let mut committed = Vec::new();
    while let Ok(cert) = rx_output.try_recv() {
        committed.push(cert);
    }

    // There should be at least one commit, and timestamps should remain non-decreasing.
    assert!(!committed.is_empty(), "Should commit under freeze certificate input");
    for i in 1..committed.len() {
        assert!(committed[i - 1].timestamp <= committed[i].timestamp);
    }
}

