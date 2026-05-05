// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Certificate;
use crate::primary::Round;
use crypto::{Digest, PublicKey};
use std::collections::HashSet;

/// Path state used to manage the status of each proposal path
#[derive(Clone, Debug)]
pub struct ProposalPathState {
    /// Path identifier (node public key)
    pub path_id: PublicKey,
    
    /// Latest certificate on this path
    pub latest_certificate: Option<Certificate>,
    
    /// Whether this path is frozen
    pub is_frozen: bool,
    
    /// Round when freezing took effect
    pub freeze_round: Round,
    
    /// Set of executable header digests
    pub executable_headers: HashSet<Digest>,
}

impl ProposalPathState {
    /// Creates a new path state
    pub fn new(path_id: PublicKey) -> Self {
        Self {
            path_id,
            latest_certificate: None,
            is_frozen: false,
            freeze_round: 0,
            executable_headers: HashSet::new(),
        }
    }

    /// Updates the latest certificate
    pub fn update_latest_certificate(&mut self, certificate: Certificate) {
        self.latest_certificate = Some(certificate);
    }

    /// Marks a header as executable
    pub fn mark_executable(&mut self, digest: Digest) {
        self.executable_headers.insert(digest);
    }

    /// Checks whether a header is executable
    pub fn is_executable(&self, digest: &Digest) -> bool {
        self.executable_headers.contains(digest)
    }

    /// Marks the path as frozen
    pub fn freeze(&mut self, freeze_round: Round) {
        self.is_frozen = true;
        self.freeze_round = freeze_round;
    }
}
