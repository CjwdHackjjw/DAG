// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::VotesAggregator;
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid certificates to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<Certificate>, Round)>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<Digest>>,
    /// Records which authors' headers have been received in each round, used to determine whether an i+1 proposal has been observed
    seen_headers: HashMap<Round, HashSet<PublicKey>>,
    /// Paths waiting for freeze results: target_path -> stall_round
    pending_freezes: HashMap<PublicKey, Round>,
    /// Headers whose votes are deferred while waiting for freeze results
    deferred_headers: HashMap<PublicKey, Vec<Header>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// Aggregates votes into a certificate.
    votes_aggregator: VotesAggregator,
    /// Frozen paths: path public key -> freeze round. Headers at or after that round are no longer accepted
    frozen_paths: HashMap<PublicKey, Round>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Certificate>, Round)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                synchronizer,
                signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                tx_consensus,
                tx_proposer,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                seen_headers: HashMap::with_capacity(2 * gc_depth as usize),
                pending_freezes: HashMap::new(),
                deferred_headers: HashMap::new(),
                current_header: Header::default(),
                votes_aggregator: VotesAggregator::new(),
                frozen_paths: HashMap::new(),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Reset the votes aggregator.
        self.current_header = header.clone();
        self.votes_aggregator = VotesAggregator::new();

        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header(&header).await
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        debug!("Processing {:?}", header);

        // Record that we have received this author's header in this round, used to determine whether an i+1 proposal has been observed.
        self.seen_headers
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.author);

        // Indicate that we are processing this header.
        self.processing
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.id.clone());

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.
        let parents = self.synchronizer.get_parents(header).await?;
        if parents.is_empty() {
            debug!("Processing of {} suspended: missing parent(s)", header.id);
            return Ok(());
        }

        // New design: each path proposes independently, and parents may come from different paths at different rounds.
        // We only need to verify that the parents exist, which the synchronizer already guarantees, without restricting their rounds.
        let _ = parents;

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            debug!("Processing of {} suspended: missing payload", header);
            return Ok(());
        }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // If this author's path is waiting for a freeze result, defer the vote for now and decide whether to send it later once the result arrives.
        if self.pending_freezes.contains_key(&header.author) {
            self.deferred_headers
                .entry(header.author)
                .or_insert_with(Vec::new)
                .push(header.clone());
            debug!(
                "Deferred voting for header {} on path {} due to pending freeze result",
                header.id, header.author
            );
            return Ok(());
        }

        // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.author)
        {
            // Determine freeze_support: whether this node supports the freeze proposal.
            // Rule: check whether we have observed the target path's proposal in round i+1.
            let freeze_support = if let Some(fp) = &header.freeze_proposal {
                let target_round = fp.stall_round + 1;
                let seen_target_header = self.seen_headers
                    .get(&target_round)
                    .map(|authors| authors.contains(&fp.target_path))
                    .unwrap_or(false);

                // Enter the "waiting for freeze result" state and temporarily defer votes for subsequent headers on the target path.
                self.pending_freezes.insert(fp.target_path, fp.stall_round);
                !seen_target_header
            } else {
                false
            };

            // Make a vote and send it to the header's creator.
            let vote = Vote::new_with_freeze(header, &self.name, freeze_support, &mut self.signature_service).await;
            debug!("Created {:?}", vote);
            if vote.origin == self.name {
                if let Err(err) = self.process_vote(vote).await {
                    match err {
                        DagError::AuthorityReuse(author) => {
                            debug!("Ignoring duplicate own vote from {}", author);
                        }
                        _ => panic!("Failed to process our own vote: {}", err),
                    }
                }
            } else {
                let address = self
                    .committee
                    .primary(&header.author)
                    .expect("Author of valid header is not in the committee")
                    .primary_to_primary;
                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                    .expect("Failed to serialize our own vote");
                let handler = self.network.send(address, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(header.round)
                    .or_insert_with(Vec::new)
                    .push(handler);
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing {:?}", vote);

        // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(certificate) =
            self.votes_aggregator
                .append(vote, &self.committee, &self.current_header)?
        {
            debug!("Assembled {:?}", certificate);

            // Broadcast the certificate.
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                .expect("Failed to serialize our own certificate");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(certificate.round())
                .or_insert_with(Vec::new)
                .extend(handlers);

            // Process the new certificate.
            self.process_certificate(certificate)
                .await
                .expect("Failed to process valid certificate");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing {:?}", certificate);

        // Process the header embedded in the certificate if we haven't already voted for it (if we already
        // voted, it means we already processed it). Since this header got certified, we are sure that all
        // the data it refers to (ie. its payload and its parents) are available. We can thus continue the
        // processing of the certificate even if we don't have them in store right now.
        if !self
            .processing
            .get(&certificate.header.round)
            .map_or_else(|| false, |x| x.contains(&certificate.header.id))
        {
            // This function may still throw an error if the storage fails.
            self.process_header(&certificate.header).await?;
        }

        // Ensure we have all the ancestors of this certificate yet. If we don't, the synchronizer will gather
        // them and trigger re-processing of this certificate.
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            debug!(
                "Processing of {:?} suspended: missing ancestors",
                certificate
            );
            return Ok(());
        }

        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        // New design: as soon as a valid certificate is received, immediately notify the proposer
        // to update the latest certificate on that path. We no longer wait for a 2f+1 quorum,
        // and each path advances independently.
        self.tx_proposer
            .send((vec![certificate.clone()], certificate.round()))
            .await
            .expect("Failed to send certificate to proposer");

        // Update frozen-path records: if the certificate contains freeze results, record the freeze round.
        for frozen_path in &certificate.frozen_paths {
            let freeze_round = certificate.header.freeze_proposal
                .as_ref()
                .map(|fp| fp.stall_round + 1)
                .unwrap_or(certificate.round());
            self.frozen_paths
                .entry(*frozen_path)
                .or_insert(freeze_round);
            debug!("Path {:?} is now frozen from round {}", frozen_path, freeze_round);
        }

        // Freeze result resolved:
        // - If the freeze passes, keep rejecting that path and drop deferred headers.
        // - If the freeze fails, send votes for the headers that were previously deferred.
        if let Some(fp) = &certificate.header.freeze_proposal {
            let target = fp.target_path;
            let frozen = certificate.frozen_paths.contains(&target);

            // Clear the pending-freeze state.
            self.pending_freezes.remove(&target);

            if frozen {
                // Freeze passed: drop the deferred queue.
                self.deferred_headers.remove(&target);
                debug!("Freeze passed for path {:?}, deferred headers dropped", target);
            } else {
                // Freeze rejected: vote on the deferred headers.
                if let Some(mut deferred) = self.deferred_headers.remove(&target) {
                    // Replay deferred votes in round order.
                    deferred.sort_by_key(|h| h.round);
                    for h in deferred {
                        debug!("Freeze rejected, resume voting for deferred header {}", h.id);
                        // Replay only if the path is not frozen and we have not already voted for this author in that round.
                        if self.frozen_paths.get(&h.author).map(|r| h.round >= *r).unwrap_or(false) {
                            continue;
                        }
                        if !self
                            .last_voted
                            .entry(h.round)
                            .or_insert_with(HashSet::new)
                            .insert(h.author)
                        {
                            continue;
                        }
                        let vote = Vote::new_with_freeze(&h, &self.name, false, &mut self.signature_service).await;
                        if vote.origin == self.name {
                            self.process_vote(vote).await?;
                        } else {
                            let address = self
                                .committee
                                .primary(&h.author)
                                .expect("Author of valid header is not in the committee")
                                .primary_to_primary;
                            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                                .expect("Failed to serialize resumed vote");
                            let handler = self.network.send(address, Bytes::from(bytes)).await;
                            self.cancel_handlers
                                .entry(h.round)
                                .or_insert_with(Vec::new)
                                .push(handler);
                        }
                    }
                }
            }
        }

        // Send it to the consensus layer.
        let id = certificate.header.id.clone();
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id.clone(), header.round)
        );

        // Reject headers on frozen paths: headers at or after the freeze round are no longer accepted.
        if let Some(&freeze_round) = self.frozen_paths.get(&header.author) {
            ensure!(
                header.round < freeze_round,
                DagError::TooOld(header.id.clone(), header.round)
            );
        }

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        ensure!(
            self.current_header.round <= vote.round,
            DagError::TooOld(vote.digest(), vote.round)
        );

        // Ensure we receive a vote on the expected header.
        ensure!(
            vote.id == self.current_header.id
                && vote.origin == self.current_header.author
                && vote.round == self.current_header.round,
            DagError::UnexpectedVote(vote.id.clone())
        );

        // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(&header).await,
                                error => error
                            }

                        },
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => self.process_vote(vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            match self.sanitize_certificate(&certificate) {
                                Ok(()) =>  self.process_certificate(certificate).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing.retain(|k, _| k >= &gc_round);
                self.seen_headers.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
