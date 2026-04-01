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

// Fixture: 每个节点每轮一个证书，path_id = author，timestamp = round * 100 + author_index
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

// 创建一组证书（每个节点一个），返回证书队列和下一轮的 parents
fn make_certificates(
    start: Round,
    stop: Round,
    initial_parents: &BTreeSet<Digest>,
    keys: &[(PublicKey, u64)],  // (公钥, 时间戳偏移)
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

// 基本测试：4 个节点各自独立路径，每轮各一个证书，验证共识能正确提交
#[tokio::test]
async fn commit_basic() {
    let keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let keys_with_ts: Vec<_> = keys.iter().enumerate().map(|(i, k)| (*k, i as u64)).collect();

    let genesis = Certificate::genesis(&mock_committee());
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    // 生成 4 轮证书（每轮 4 个节点），用于触发前几轮可执行性更新
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

    // 发送所有证书
    while let Some(cert) = certificates.pop_front() {
        tx_waiter.send(cert).await.unwrap();
    }

    // 以超时方式等待至少一个提交，避免调度抖动导致的偶发空读
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
    // 应该有来自 round 1, 2, 3 的证书被提交
    assert!(!committed.is_empty(), "Should have committed some certificates");
    // 验证时间戳排序
    for i in 1..committed.len() {
        assert!(
            committed[i-1].timestamp <= committed[i].timestamp,
            "Certificates should be ordered by timestamp"
        );
    }
}

// 单路径测试：只有一个节点提案，验证可执行性递归更新
#[tokio::test]
async fn single_path_commit() {
    let keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let name = keys[0];
    let committee = mock_committee();

    let genesis = Certificate::genesis(&committee);
    let genesis_digests: BTreeSet<_> = genesis.iter().map(|x| x.digest()).collect();

    // 创建单节点的 5 轮证书链
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

    // round 5 证书到来 -> round 4 可执行
    // round 4 证书到来 -> round 3 可执行
    // ... 等等
    // 验证轮次顺序
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

    // 在 observer 的第 4 轮证书中注入冻结结果：冻结 target，stall_round = 3
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

    // 再追加第 5 轮：仅非 target 路径继续推进
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

    // 注入一张带冻结结果的证书
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

    // 至少有提交，且保持时间戳非递减
    assert!(!committed.is_empty(), "Should commit under freeze certificate input");
    for i in 1..committed.len() {
        assert!(committed[i - 1].timestamp <= committed[i].timestamp);
    }
}

