// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, FreezeProposal, Header};
use crate::path_state::PathState;
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::debug;
#[cfg(feature = "benchmark")]
use log::info;
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// Committee information
    committee: Committee,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,
    /// Freeze check interval (m parameter)
    freeze_check_interval: Round,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(Vec<Certificate>, Round)>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(Digest, WorkerId)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,

    /// The current round of the dag.
    round: Round,
    /// The latest round we have proposed on our own path.
    last_proposed_round: Round,
    /// Timestamp of the last proposal attempt (used for same-round cooldown).
    last_proposed_at: Option<Instant>,
    /// Stores the latest certificate for each node's path
    latest_certificates: HashMap<PublicKey, Option<Certificate>>,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(Digest, WorkerId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// Path states for tracking stalled paths
    path_states: HashMap<PublicKey, PathState>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        freeze_check_interval: Round,
        rx_core: Receiver<(Vec<Certificate>, Round)>,
        rx_workers: Receiver<(Digest, WorkerId)>,
        tx_core: Sender<Header>,
    ) {

        let committee = committee.clone();
        let genesis = Certificate::genesis(&committee);
        let mut latest_certificates = HashMap::new();
        let mut path_states = HashMap::new();

        // Initialize latest_certificates and path_states with genesis certificates
        for cert in &genesis {
            let path_id = cert.header.path_id;
            latest_certificates.insert(path_id, Some(cert.clone()));
            path_states.insert(path_id, PathState::new(path_id));
        }

        tokio::spawn(async move {
            Self {
                name,
                committee,
                signature_service,
                header_size,
                max_header_delay,
                freeze_check_interval,
                rx_core,
                rx_workers,
                tx_core,
                round: 1,
                last_proposed_round: 0,
                last_proposed_at: None,
                latest_certificates,
                digests: Vec::with_capacity(2 * header_size),
                payload_size: 0,
                path_states,
            }
            .run()
            .await;
        });
    }

    async fn make_header(&mut self) {
        // 构建 parents：引用所有节点对应路径最新的证书
        // 已冻结的路径直接跳过，不再引用
        let mut parents = std::collections::BTreeSet::new();
        for (path_id, cert_opt) in &self.latest_certificates {
            if let Some(cert) = cert_opt {
                let is_frozen = self.path_states
                    .get(path_id)
                    .map(|ps| ps.is_frozen)
                    .unwrap_or(false);
                if !is_frozen {
                    parents.insert(cert.digest());
                }
            }
        }

        // 生成冻结提案（如果需要）
        let freeze_proposal = self.generate_freeze_proposal().await;

        // Make a new header.
        let header = Header::new_with_freeze(
            self.name,
            self.round,
            self.digests.drain(..).collect(),
            parents,
            freeze_proposal,
            &mut self.signature_service,
        )
        .await;
        debug!("Created {:?}", header);

        #[cfg(feature = "benchmark")]
        for digest in header.payload.keys() {
            // NOTE: This log entry is used to compute performance.
            info!("Created {} -> {:?}", header, digest);
        }

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");

        // 记录自己路径最新已提案轮次和提案时间
        self.last_proposed_round = self.round;
        self.last_proposed_at = Some(Instant::now());
    }

    /// 生成冻结提案（如果需要）
    async fn generate_freeze_proposal(&mut self) -> Option<FreezeProposal> {
        let m = self.freeze_check_interval;

        for (target_path, path_state) in &self.path_states {
            if path_state.is_frozen {
                continue;
            }

            // 获取目标路径最新轮次
            let target_latest_round = path_state.latest_certificate
                .as_ref()
                .map(|c| c.round())
                .unwrap_or(0);

            // 先检查自己轮次和目标路径轮次差是否至少 m，不满足则目标路径尚未停滞
            if self.round < target_latest_round + m {
                continue;
            }

            // stall_round：目标路径停滞的那一轮（最新已知轮次）
            let stall_round = target_latest_round;

            // 计算当前轮是否恰好是某个检查点：(self.round - stall_round) 必须是 m 的整数倍
            let diff = self.round.saturating_sub(stall_round);
            if diff == 0 || diff % m != 0 {
                continue;
            }
            let k = diff / m; // 第 k 个检查点（k >= 1）

            let observer = self.select_observer(target_path, stall_round, k as u64);
            if observer == self.name {
                return Some(FreezeProposal {
                    target_path: *target_path,
                    stall_round,
                    observer: self.name,
                });
            }
        }

        None
    }

    /// 观察节点选择算法
    fn select_observer(&self, target_path: &PublicKey, stall_round: Round, k: u64) -> PublicKey {
        let check_round = stall_round + k * self.freeze_check_interval;

        // 构建种子：target_path_pub + stall_round + k*m
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&target_path.0);
        seed_data.extend_from_slice(&stall_round.to_le_bytes());
        seed_data.extend_from_slice(&check_round.to_le_bytes());

        // 计算哈希作为随机种子
        let hash_result = Sha512::digest(&seed_data);
        let seed = u64::from_le_bytes(
            hash_result[..8].try_into().unwrap_or([0; 8])
        );

        // 在 n-1 个节点中随机选择（排除目标节点本身）
        let mut candidates: Vec<_> = self.committee.authorities.keys()
            .filter(|name| *name != target_path)
            .copied()
            .collect();

        if candidates.is_empty() {
            return self.name;
        }

        candidates[(seed as usize) % candidates.len()]
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.round);

        let timer = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);

        loop {
            // 提案条件：
            // 1. 自己路径上一轮已经有了证书（自身路径的上一轮 certificate 已存在）
            // 2. payload 足够 或 timer 超时
            let own_prev_cert_ready = self.latest_certificates
                .get(&self.name)
                .and_then(|c| c.as_ref())
                .map(|c| c.round() == self.round - 1)
                .unwrap_or(self.round == 1); // round 1 时创世证书已就绪

            // 约束：只有自己路径上一轮已经“生成提案”才允许进入下一轮提案（round 1 例外）
            let own_prev_proposed_ready = self.round == 1 || self.last_proposed_round >= self.round - 1;

            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();

            // 同一轮次内允许重复提案，但需要满足 3 * max_header_delay 的冷却时间。
            let same_round_cooldown_elapsed = if self.last_proposed_round == self.round {
                self.last_proposed_at
                    .map(|t| t.elapsed() >= Duration::from_millis(self.max_header_delay * 3))
                    .unwrap_or(true)
            } else {
                true
            };

            if own_prev_cert_ready
                && own_prev_proposed_ready
                && (enough_digests || timer_expired)
                && same_round_cooldown_elapsed
            {
                // Make a new header.
                self.make_header().await;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

            tokio::select! {
                Some((certs, _round)) = self.rx_core.recv() => {
                    // 更新各路径最新证书
                    for cert in certs {
                        let path_id = cert.header.path_id;
                        let cert_round = cert.round();

                        // 更新冻结状态：如果证书包含冻结结果
                        for frozen_path in &cert.frozen_paths {
                            let freeze_round = cert.header.freeze_proposal
                                .as_ref()
                                .map(|fp| fp.stall_round + 1)
                                .unwrap_or(cert_round);
                            let ps = self.path_states
                                .entry(*frozen_path)
                                .or_insert_with(|| PathState::new(*frozen_path));
                            if !ps.is_frozen {
                                ps.freeze(freeze_round);
                                debug!("Proposer: path {:?} frozen at round {}", frozen_path, freeze_round);
                            }
                        }

                        // 更新路径状态
                        let ps = self.path_states
                            .entry(path_id)
                            .or_insert_with(|| PathState::new(path_id));

                        ps.update_latest_certificate(cert.clone());
                        self.latest_certificates.insert(path_id, Some(cert.clone()));

                        // 如果是自己路径的证书，推进本地轮次
                        if path_id == self.name {
                            if cert_round >= self.round {
                                self.round = cert_round + 1;
                                debug!("Own path advanced to round {}", self.round);
                            }
                        }
                    }
                }
                Some((digest, worker_id)) = self.rx_workers.recv() => {
                    self.payload_size += digest.size();
                    self.digests.push((digest, worker_id));
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}
