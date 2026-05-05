// Copyright(C) Facebook, Inc. and its affiliates.
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use primary::{Certificate, Round};
use std::cmp::{max, Ordering};
use std::collections::{BinaryHeap, HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;


type RoundPathIndex = HashMap<Round, HashMap<PublicKey, Certificate>>;

type DigestIndex = HashMap<Digest, Certificate>;

/// Wrapper for an executable header, used in the min-heap ordered by timestamp.
/// When the certificate corresponding to a header arrives, the same-path predecessor
/// of that header becomes marked as executable and is inserted into the ordering queue.
#[derive(PartialEq, Clone)]
struct ExecutableHeader {
    /// Median timestamp of the certificate corresponding to this header, in milliseconds
    timestamp: u64,
    /// Round of this header
    round: Round,
    /// Proposal path this header belongs to, identified by node public key
    path_id: PublicKey,
    /// Digest of the header
    digest: Digest,
    /// Full certificate, kept for final output
    certificate: Certificate,
}

impl Ord for ExecutableHeader {
    fn cmp(&self, other: &Self) -> Ordering {
        // Rust's `BinaryHeap` is a max-heap, so the comparison is reversed here to place
        // the smallest timestamp at the top of the heap.
        // When timestamps tie, the higher round is preferred to prioritize newer proposals.
        other.timestamp.cmp(&self.timestamp)
            .then_with(|| other.round.cmp(&self.round))
    }
}

impl PartialOrd for ExecutableHeader {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for ExecutableHeader {}

/// Consensus state for a single proposal path.
/// Each node owns one path, and the consensus layer maintains this state independently for every path.
struct ConsensusPathState {
    /// Path identifier, corresponding to the node public key
    path_id: PublicKey,
    /// Whether this path has been frozen after the observer's freeze proposal passed for a failed node
    is_frozen: bool,

    freeze_round: Round,

    executable_headers: HashMap<Digest, (Round, u64, Certificate)>,

    highest_executable_round: Round,

    highest_executable_digest: Option<Digest>,
}

impl ConsensusPathState {
    fn new(path_id: PublicKey) -> Self {
        Self {
            path_id,
            is_frozen: false,
            freeze_round: 0,
            executable_headers: HashMap::new(),
            highest_executable_round: 0,
            highest_executable_digest: None,
        }
    }

    fn mark_executable(&mut self, cert: &Certificate) {
        let digest = cert.header.id.clone();
        let round = cert.round();
        let timestamp = cert.timestamp;
        self.executable_headers.insert(digest.clone(), (round, timestamp, cert.clone()));
        // Update only the highest-round record; executable headers from older rounds remain in the set.
        if round > self.highest_executable_round {
            self.highest_executable_round = round;
            self.highest_executable_digest = Some(digest);
        }
    }

    /// Checks whether a header, identified by its digest, has been marked executable.
    fn is_executable(&self, digest: &Digest) -> bool {
        self.executable_headers.contains_key(digest)
    }

    /// Freezes this path so that it no longer participates in consensus decisions starting from `freeze_round`.
    fn freeze(&mut self, freeze_round: Round) {
        self.is_frozen = true;
        self.freeze_round = freeze_round;
    }
}

/// Global consensus state, including the DAG view, per-path state, the executable queue, and commit records.
struct State {
    /// Highest committed round across the entire network
    last_committed_round: Round,
    /// Highest committed round for each path
    last_committed: HashMap<PublicKey, Round>,
    /// DAG index by round and path
    round_path_index: RoundPathIndex,
    /// DAG index by certificate digest
    digest_index: DigestIndex,
    /// Independent state for each path
    path_states: HashMap<PublicKey, ConsensusPathState>,
    /// Priority queue of executable headers ordered by timestamp, effectively a min-heap by earliest timestamp
    executable_queue: BinaryHeap<ExecutableHeader>,
    /// Set of committed (executed) header digests, used to prevent duplicate commits
    executed: HashSet<Digest>,
}

impl State {
    /// Initializes consensus state from genesis certificates.
    /// Genesis certificates represent the starting point of each path at round 0.
    /// They are not committed, but are used to initialize the DAG.
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis_map = genesis
            .into_iter()
            .map(|x| (x.origin(), x))
            .collect::<HashMap<_, _>>();
        // Initialize `ConsensusPathState` for every path.
        let mut path_states = HashMap::new();
        for name in genesis_map.keys() {
            path_states.insert(*name, ConsensusPathState::new(*name));
        }

        let mut digest_index = HashMap::new();
        for cert in genesis_map.values() {
            digest_index.insert(cert.digest(), cert.clone());
        }

        Self {
            last_committed_round: 0,
            last_committed: genesis_map.iter().map(|(x, y)| (*x, y.round())).collect(),
            // Store all genesis certificates in round 0.
            round_path_index: [(0, genesis_map)].iter().cloned().collect(),
            digest_index,
            path_states,
            executable_queue: BinaryHeap::new(),
            executed: HashSet::new(),
        }
    }

    /// When a new certificate arrives, recursively mark same-path predecessor headers as executable.
    ///
    /// Core logic:
    /// - A header becomes executable when the next-round certificate on the same path arrives
    /// - Example: when certificate A3 arrives, A2 becomes executable, and then the algorithm recursively checks whether A1, the same-path parent of A2, should also become executable
    /// - Only same-path predecessors, i.e. those with the same `path_id`, are processed recursively.
    ///   References to different paths are used only for network synchronization
    /// - Recursion stops when an already executable header is encountered, avoiding duplicate work
    fn update_executable(&mut self, cert: &Certificate, queue: &mut BinaryHeap<ExecutableHeader>) {
        let cur_path = cert.header.path_id;

        for parent_digest in &cert.header.parents {
            // Use the digest index for O(1) parent-certificate lookup.
            let parent_cert = self.digest_index.get(parent_digest).cloned();

            if let Some(pc) = parent_cert {
                // Process only same-path predecessors.
                if pc.header.path_id == cur_path {
                    let hdr_digest = pc.header.id.clone();
                    let ps = self.path_states
                        .entry(cur_path)
                        .or_insert_with(|| ConsensusPathState::new(cur_path));
                    if !ps.is_executable(&hdr_digest) {
                        ps.mark_executable(&pc);
                        queue.push(ExecutableHeader {
                            timestamp: pc.timestamp,
                            round: pc.round(),
                            path_id: cur_path,
                            digest: hdr_digest,
                            certificate: pc.clone(),
                        });
                        // Recursively check whether the same-path predecessor of this parent should also become executable.
                        self.update_executable(&pc, queue);
                    }
                }
            }
        }
    }

    /// Handles freeze results: when a path is frozen, ensure its last valid header is marked executable,
    /// then freeze the path formally.
    /// Rule: if the stall round is i, the freeze round is i+1.
    /// When the freeze passes, the header at round i-1 must already be marked executable so that no historical proposal is lost.
    fn apply_frozen_paths(&mut self, cert: &Certificate, queue: &mut BinaryHeap<ExecutableHeader>) {
        let fp = match &cert.header.freeze_proposal {
            Some(fp) => fp.clone(),
            None => return, // Skip certificates without a freeze proposal.
        };
        for frozen_path in &cert.frozen_paths {
            // Step 1: ensure the header at stall_round - 1 has become executable.
            // If the node stalled at round i, then the header at round i-1 is its last valid header.
            if fp.stall_round > 0 {
                let prev = self.round_path_index
                    .get(&(fp.stall_round.saturating_sub(1)))
                    .and_then(|m| m.get(frozen_path))
                    .cloned();
                if let Some(prev_cert) = prev {
                    let ps = self.path_states
                        .entry(*frozen_path)
                        .or_insert_with(|| ConsensusPathState::new(*frozen_path));
                    if !ps.is_executable(&prev_cert.header.id) {
                        ps.mark_executable(&prev_cert);
                        queue.push(ExecutableHeader {
                            timestamp: prev_cert.timestamp,
                            round: prev_cert.round(),
                            path_id: *frozen_path,
                            digest: prev_cert.header.id.clone(),
                            certificate: prev_cert,
                        });
                    }
                }
            }
            // Step 2: formally freeze the path, with freeze_round = stall_round + 1.
            // Headers on this path at freeze_round and beyond no longer participate in consensus.
            let ps = self.path_states
                .entry(*frozen_path)
                .or_insert_with(|| ConsensusPathState::new(*frozen_path));
            ps.freeze(fp.stall_round + 1);
            debug!("Path {:?} frozen at round {}", frozen_path, fp.stall_round + 1);
        }
    }

    /// Checks whether all executable headers on a frozen path have already been committed.
    /// If so, the path can be completely excluded from consensus decisions.
    fn is_frozen_fully_executed(&self, path_id: &PublicKey) -> bool {
        match self.path_states.get(path_id) {
            Some(ps) if ps.is_frozen =>
                ps.executable_headers.keys().all(|d| self.executed.contains(d)),
            _ => false,
        }
    }

    /// Consensus decision logic: try to commit a batch of sorted executable headers.
    ///
    /// Decision procedure:
    /// 1. Precondition: every path participating in the decision (paths not fully frozen yet)
    ///    must have at least one executable header. Otherwise, some path has not advanced
    ///    far enough, so this round is skipped until more certificates arrive.
    /// 2. Among the highest-round executable headers of each path, choose the one with the
    ///    earliest timestamp as the commit target. Break ties by preferring the higher round.
    /// 3. Pop the target and all unexecuted headers with timestamps \<= target.timestamp from
    ///    the priority queue to form the execution set. This guarantees that headers outside
    ///    the set were proposed later than those inside it.
    /// 4. Commit the execution set in ascending timestamp order and update commit records.
    fn try_commit(&mut self) -> Vec<Certificate> {
        // Step 1: check the preconditions.
        // Iterate over all paths and ensure that every participating path has an executable header.
        // A participating path is either an unfrozen path or a frozen path that still has unexecuted headers.
        for (path_id, ps) in &self.path_states {
            if ps.is_frozen && self.is_frozen_fully_executed(path_id) {
                continue; // Exclude paths that are frozen and already fully executed.
            }
            if ps.highest_executable_digest.is_none() {
                // This path has no executable header yet; wait until its certificate arrives before deciding.
                return Vec::new();
            }
        }

        // Step 2: choose the commit target.
        // Iterate over all paths, take the highest-round executable header on each path,
        // and choose the one with the earliest timestamp as the target.
        // Semantically, the target is the most lagging yet earliest proposed header among all paths,
        // and all headers before it can be safely committed because the target has been seen by a quorum.
        let mut target: Option<ExecutableHeader> = None;
        for (path_id, ps) in &self.path_states {
            if ps.is_frozen && self.is_frozen_fully_executed(path_id) {
                continue;
            }
            if let Some(d) = &ps.highest_executable_digest {
                if let Some((round, timestamp, cert)) = ps.executable_headers.get(d) {
                    let candidate = ExecutableHeader {
                        timestamp: *timestamp,
                        round: *round,
                        path_id: *path_id,
                        digest: d.clone(),
                        certificate: cert.clone(),
                    };
                    let replace = match &target {
                        None => true,
                        // Prefer the earlier timestamp; break ties by preferring the higher round.
                        Some(t) => candidate.timestamp < t.timestamp
                            || (candidate.timestamp == t.timestamp && candidate.round > t.round),
                    };
                    if replace { target = Some(candidate); }
                }
            }
        }

        let target = match target {
            Some(t) => t,
            None => return Vec::new(),
        };

        // Skip the target if it has already been executed, to avoid duplicate commits.
        if self.executed.contains(&target.digest) {
            return Vec::new();
        }

        // Step 3: build the execution set.
        // Pop all unexecuted headers with timestamps \<= target.timestamp from the priority queue,
        // together with the target itself, to form the execution set.
        // Guarantee: any header outside the execution set has a larger timestamp and was therefore proposed later.
        let mut execution_set: Vec<ExecutableHeader> = Vec::new();
        let mut remaining = BinaryHeap::new();
        while let Some(e) = self.executable_queue.pop() {
            let before_target = e.timestamp < target.timestamp
                || (e.timestamp == target.timestamp && e.round <= target.round);
            if before_target {
                if !self.executed.contains(&e.digest) {
                    execution_set.push(e);
                }
            } else {
                // Keep headers with larger timestamps in the queue for the next decision round.
                remaining.push(e);
            }
        }
        self.executable_queue = remaining;

        // Ensure the target itself is included in the execution set, even if it was selected directly from path_states instead of the queue.
        if !execution_set.iter().any(|e| e.digest == target.digest) {
            if !self.executed.contains(&target.digest) {
                execution_set.push(target);
            }
        }

        // Step 4: sort by ascending timestamp and then commit.
        // Break ties by ascending round for deterministic ordering.
        execution_set.sort_by_key(|e| (e.timestamp, e.round));
        let certs: Vec<Certificate> = execution_set.iter().map(|e| e.certificate.clone()).collect();

        // Update commit records.
        for e in &execution_set {
            self.executed.insert(e.digest.clone());
            self.last_committed
                .entry(e.path_id)
                .and_modify(|r| *r = max(*r, e.round))
                .or_insert(e.round);
        }
        self.last_committed_round = *self.last_committed.values().max().unwrap_or(&0);
        certs
    }
}

/// Main consensus engine.
/// Receives certificates from the primary layer, maintains the DAG and path states,
/// and outputs the committed certificate sequence ordered by timestamp.
pub struct Consensus {
    /// Committee configuration containing all node information
    committee: Committee,
    /// Garbage-collection depth; data older than this depth can be cleaned up
    gc_depth: Round,
    /// Receives certificates from the primary core
    rx_primary: Receiver<Certificate>,
    /// Sends committed certificates back to the primary core to trigger garbage collection
    tx_primary: Sender<Certificate>,
    /// Outputs the committed certificate sequence to the upper layer
    tx_output: Sender<Certificate>,
    /// Genesis certificate set, one for each path at round 0
    genesis: Vec<Certificate>,
}

impl Consensus {
    /// Starts the consensus engine in a dedicated tokio task.
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
            }
            .run()
            .await;
        });
    }

    /// Main consensus loop: continuously receives certificates and drives consensus progress.
    async fn run(&mut self) {
        let mut state = State::new(self.genesis.clone());

        while let Some(certificate) = self.rx_primary.recv().await {
            debug!("Processing {:?}", certificate);
            let round = certificate.round();
            let origin = certificate.origin();

            // Step 1: insert the new certificate into the DAG.
            // Store it by round and path so that update_executable can find it recursively.
            state
                .round_path_index
                .entry(round)
                .or_insert_with(HashMap::new)
                .insert(origin, certificate.clone());
            state.digest_index.insert(certificate.digest(), certificate.clone());

            // Step 2: process freeze results.
            // If this certificate contains a freeze proposal supported by more than 2f+1 nodes, freeze the corresponding path.
            if !certificate.frozen_paths.is_empty() {
                let cert_clone = certificate.clone();
                let mut tmp_queue = BinaryHeap::new();
                state.apply_frozen_paths(&cert_clone, &mut tmp_queue);
                // Merge the newly executable headers into the global priority queue.
                for e in tmp_queue { state.executable_queue.push(e); }
            }

            // Step 3: update executability of same-path predecessors.
            // The arrival of a new certificate means that its same-path predecessor may become executable.
            let mut tmp_queue = BinaryHeap::new();
            state.update_executable(&certificate, &mut tmp_queue);
            for e in tmp_queue { state.executable_queue.push(e); }

            // Step 4: try the consensus decision.
            // Check whether commit conditions are satisfied; if so, commit the sequence.
            let sequence = state.try_commit();

            if sequence.is_empty() {
                continue; // Conditions are not satisfied yet; wait for more certificates.
            }

            // Step 5: output the committed certificate sequence.
            for cert in sequence {
                #[cfg(not(feature = "benchmark"))]
                info!("Committed {}", cert.header);

                // In benchmark mode, record each payload digest for performance analysis.
                #[cfg(feature = "benchmark")]
                for digest in cert.header.payload.keys() {
                    info!("Committed {} -> {:?}", cert.header, digest);
                }

                // Notify the primary core that this certificate has been committed so it can trigger garbage collection.
                self.tx_primary
                    .send(cert.clone())
                    .await
                    .expect("Failed to send certificate to primary");

                // Output to the upper layer.
                if let Err(e) = self.tx_output.send(cert).await {
                    warn!("Failed to output certificate: {}", e);
                }
            }
        }
    }
}
