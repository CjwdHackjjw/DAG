// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote};
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
    /// 收集所有投票的时间戳，用于计算中位数
    timestamps: Vec<u64>,
    /// 收集冻结投票结果
    freeze_votes: HashMap<PublicKey, bool>,
    /// 支持冻结的总 stake
    freeze_support_weight: Stake,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
            timestamps: Vec::new(),
            freeze_votes: HashMap::new(),
            freeze_support_weight: 0,
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        // 收集时间戳
        self.timestamps.push(vote.timestamp);

        // 收集冻结投票
        if header.freeze_proposal.is_some() {
            self.freeze_votes.insert(author, vote.freeze_support);
            if vote.freeze_support {
                self.freeze_support_weight += committee.stake(&author);
            }
        }

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.

            // 计算时间戳中位数
            let median_ts = Certificate::calculate_median_timestamp(&self.timestamps);

            // 判断是否冻结
            let mut frozen_paths = HashSet::new();
            if let Some(freeze_proposal) = &header.freeze_proposal {
                if self.freeze_support_weight >= committee.quorum_threshold() {
                    frozen_paths.insert(freeze_proposal.target_path);
                }
            }

            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
                timestamp: median_ts,
                freeze_votes: self.freeze_votes.clone(),
                frozen_paths,
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<PublicKey>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority contributes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        self.weight += committee.stake(&origin);
        self.certificates.push(certificate);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}
