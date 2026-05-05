// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, FreezeProposal, Header};
use crate::path_state::ProposalPathState;
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
    /// Holds path states for tracking latest certificates and frozen paths
    path_states: HashMap<PublicKey, ProposalPathState>,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(Digest, WorkerId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
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
        let mut path_states = HashMap::new();

        // Initialize path_states with genesis certificates.
        for cert in genesis {
            let path_id = cert.header.path_id;
            let mut state = ProposalPathState::new(path_id);
            state.update_latest_certificate(cert);
            path_states.insert(path_id, state);
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
                path_states,
                digests: Vec::with_capacity(2 * header_size),
                payload_size: 0,
            }
            .run()
            .await;
        });
    }

    async fn make_header(&mut self) {
        // Build parents by referencing the latest certificate on each node's path.
        // Skip frozen paths because they should no longer be referenced.
        let mut parents = std::collections::BTreeSet::new();
        for state in self.path_states.values() {
            if state.is_frozen {
                continue;
            }
            if let Some(cert) = &state.latest_certificate {
                parents.insert(cert.digest());
            }
        }

        // Generate a freeze proposal if needed.
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

        // Record the latest round proposed on our own path.
        self.last_proposed_round = self.round;
    }

    /// Generates a freeze proposal if needed.
    async fn generate_freeze_proposal(&mut self) -> Option<FreezeProposal> {
        let m = self.freeze_check_interval;

        for (target_path, path_state) in &self.path_states {
            if path_state.is_frozen {
                continue;
            }

            // Get the latest round of the target path.
            let target_latest_round = path_state.latest_certificate
                .as_ref()
                .map(|c| c.round())
                .unwrap_or(0);

            // First check whether our round is at least m rounds ahead of the target path; otherwise the target path is not stalled yet.
            if self.round < target_latest_round + m {
                continue;
            }

            // stall_round is the round where the target path stalled, i.e., its latest known round.
            let stall_round = target_latest_round;

            // Check whether the current round is exactly a checkpoint: (self.round - stall_round) must be a multiple of m.
            let diff = self.round.saturating_sub(stall_round);
            if diff == 0 || diff % m != 0 {
                continue;
            }
            let k = diff / m; // The k-th checkpoint (k >= 1).

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

    /// Observer selection algorithm.
    fn select_observer(&self, target_path: &PublicKey, stall_round: Round, k: u64) -> PublicKey {
        let check_round = stall_round + k * self.freeze_check_interval;

        // Build the seed from target_path_pub + stall_round + k*m.
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&target_path.0);
        seed_data.extend_from_slice(&stall_round.to_le_bytes());
        seed_data.extend_from_slice(&check_round.to_le_bytes());

        // Hash the seed data to derive a random seed.
        let hash_result = Sha512::digest(&seed_data);
        let seed = u64::from_le_bytes(
            hash_result[..8].try_into().unwrap_or([0; 8])
        );

        // Randomly select one of the n-1 nodes, excluding the target node itself.
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
            // Proposal conditions:
            // 1. The previous-round certificate on our own path is ready.
            // 2. Either the payload is large enough or the timer has expired.
            let own_prev_cert_ready = self.path_states
                .get(&self.name)
                .and_then(|ps| ps.latest_certificate.as_ref())
                .map(|c| c.round() == self.round - 1)
                .unwrap_or(self.round == 1); // The genesis certificate is ready at round 1.

            // Constraint: moving to the next proposal round is allowed only after our own path has produced a proposal in the previous round, except for round 1.
            let own_prev_proposed_ready = self.round == 1 || self.last_proposed_round >= self.round - 1;

            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();

            // The first proposal in a round can be triggered by a full payload or by timer expiration.
            // If this round has already been proposed, allow reproposal only after the timer expires
            // to avoid replacing the current proposal immediately with a new payload while late votes are still arriving.
            let round_already_proposed = self.last_proposed_round == self.round;
            let proposal_trigger = if round_already_proposed {
                timer_expired
            } else {
                enough_digests || timer_expired
            };

            if own_prev_cert_ready && own_prev_proposed_ready && proposal_trigger {
                // Make a new header.
                self.make_header().await;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

            tokio::select! {
                Some((certs, _round)) = self.rx_core.recv() => {
                    // Update the latest certificate for each path.
                    for cert in certs {
                        let path_id = cert.header.path_id;
                        let cert_round = cert.round();

                        // Update freeze state if the certificate contains freeze results.
                        for frozen_path in &cert.frozen_paths {
                            let freeze_round = cert.header.freeze_proposal
                                .as_ref()
                                .map(|fp| fp.stall_round + 1)
                                .unwrap_or(cert_round);
                            let ps = self.path_states
                                .entry(*frozen_path)
                                .or_insert_with(|| ProposalPathState::new(*frozen_path));
                            if !ps.is_frozen {
                                ps.freeze(freeze_round);
                                debug!("Proposer: path {:?} frozen at round {}", frozen_path, freeze_round);
                            }
                        }

                        // Update the path state.
                        let ps = self.path_states
                            .entry(path_id)
                            .or_insert_with(|| ProposalPathState::new(path_id));

                        ps.update_latest_certificate(cert.clone());

                        // Advance the local round if this certificate belongs to our own path.
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
