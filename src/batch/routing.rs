//! Ambiguous file routing logic.
//!
//! Implements the routing decision flowchart from
//! `docs/batch-store/08-ambiguous-routing.md`.

use super::types::{AmbiguousReason, ConfidenceBand, RoutingStatus};
use crate::types::Isa;

/// Routing decision parameters.
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Minimum confidence to classify (below → ambiguous/low_conf).
    /// Default: 0.30
    pub min_confidence: f64,
    /// Minimum margin over runner-up (below → ambiguous/low_margin).
    /// Default: 0.20
    pub min_margin: f64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.30,
            min_margin: 0.20,
        }
    }
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub status: RoutingStatus,
    pub ambiguous_reason: Option<AmbiguousReason>,
    pub confidence_band: ConfidenceBand,
}

/// Input data needed to make a routing decision.
pub struct RoutingInput<'a> {
    /// Did the classifier return an error?
    pub is_error: bool,
    /// Primary ISA classification.
    pub isa: &'a Isa,
    /// Primary ISA confidence (0.0 - 1.0).
    pub confidence: f64,
    /// Raw score of the winner.
    pub winner_score: i64,
    /// Raw score of the runner-up (0 if no runner-up).
    pub runner_up_score: i64,
}

impl<'a> RoutingInput<'a> {
    /// Compute the margin: `(winner - runner_up) / runner_up`.
    /// Returns 1.0 if runner_up is 0 (no competition).
    pub fn margin(&self) -> f64 {
        if self.runner_up_score <= 0 {
            1.0
        } else {
            (self.winner_score - self.runner_up_score) as f64 / self.runner_up_score as f64
        }
    }
}

/// Make a routing decision for a classified file.
///
/// Rules are evaluated in priority order (first match wins):
/// 1. Error → ambiguous/error
/// 2. Unknown ISA → ambiguous/unknown_isa
/// 3. Low confidence → ambiguous/low_conf
/// 4. Low margin → ambiguous/low_margin
/// 5. Otherwise → classified
pub fn route(config: &RoutingConfig, input: &RoutingInput) -> RoutingDecision {
    let confidence_band = ConfidenceBand::from_confidence(input.confidence);

    // Rule 1: Classification error
    if input.is_error {
        return RoutingDecision {
            status: RoutingStatus::Ambiguous,
            ambiguous_reason: Some(AmbiguousReason::Error),
            confidence_band,
        };
    }

    // Rule 2: Unknown ISA
    if matches!(input.isa, Isa::Unknown(_)) {
        return RoutingDecision {
            status: RoutingStatus::Ambiguous,
            ambiguous_reason: Some(AmbiguousReason::UnknownIsa),
            confidence_band,
        };
    }

    // Rule 3: Low confidence
    if input.confidence < config.min_confidence {
        return RoutingDecision {
            status: RoutingStatus::Ambiguous,
            ambiguous_reason: Some(AmbiguousReason::LowConf),
            confidence_band,
        };
    }

    // Rule 4: Low margin
    if input.margin() < config.min_margin {
        return RoutingDecision {
            status: RoutingStatus::Ambiguous,
            ambiguous_reason: Some(AmbiguousReason::LowMargin),
            confidence_band,
        };
    }

    // Passed all checks → classified
    RoutingDecision {
        status: RoutingStatus::Classified,
        ambiguous_reason: None,
        confidence_band,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RoutingConfig {
        RoutingConfig::default()
    }

    #[test]
    fn test_route_error() {
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: true,
                isa: &Isa::AArch64,
                confidence: 0.0,
                winner_score: 0,
                runner_up_score: 0,
            },
        );
        assert_eq!(decision.status, RoutingStatus::Ambiguous);
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::Error));
    }

    #[test]
    fn test_route_unknown_isa() {
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::Unknown(0x1234),
                confidence: 0.50,
                winner_score: 1000,
                runner_up_score: 500,
            },
        );
        assert_eq!(decision.status, RoutingStatus::Ambiguous);
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::UnknownIsa));
    }

    #[test]
    fn test_route_low_confidence() {
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::AArch64,
                confidence: 0.15,
                winner_score: 1000,
                runner_up_score: 200,
            },
        );
        assert_eq!(decision.status, RoutingStatus::Ambiguous);
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::LowConf));
    }

    #[test]
    fn test_route_low_margin() {
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::AArch64,
                confidence: 0.50,
                winner_score: 1000,
                runner_up_score: 900, // margin = 100/900 = 0.111 < 0.20
            },
        );
        assert_eq!(decision.status, RoutingStatus::Ambiguous);
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::LowMargin));
    }

    #[test]
    fn test_route_classified() {
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::AArch64,
                confidence: 0.85,
                winner_score: 1000,
                runner_up_score: 500, // margin = 500/500 = 1.0
            },
        );
        assert_eq!(decision.status, RoutingStatus::Classified);
        assert_eq!(decision.ambiguous_reason, None);
        assert_eq!(decision.confidence_band, ConfidenceBand::High);
    }

    #[test]
    fn test_margin_no_runner_up() {
        let input = RoutingInput {
            is_error: false,
            isa: &Isa::X86_64,
            confidence: 0.90,
            winner_score: 5000,
            runner_up_score: 0,
        };
        assert_eq!(input.margin(), 1.0);
    }

    #[test]
    fn test_confidence_bands() {
        assert_eq!(ConfidenceBand::from_confidence(0.95), ConfidenceBand::High);
        assert_eq!(
            ConfidenceBand::from_confidence(0.65),
            ConfidenceBand::Medium
        );
        assert_eq!(ConfidenceBand::from_confidence(0.35), ConfidenceBand::Low);
        assert_eq!(
            ConfidenceBand::from_confidence(0.15),
            ConfidenceBand::VeryLow
        );
    }

    #[test]
    fn test_rule_priority_error_beats_unknown() {
        // Error takes priority over unknown ISA
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: true,
                isa: &Isa::Unknown(0),
                confidence: 0.0,
                winner_score: 0,
                runner_up_score: 0,
            },
        );
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::Error));
    }

    #[test]
    fn test_rule_priority_unknown_beats_low_conf() {
        // Unknown ISA takes priority over low confidence
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::Unknown(0),
                confidence: 0.10,
                winner_score: 100,
                runner_up_score: 90,
            },
        );
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::UnknownIsa));
    }

    #[test]
    fn test_rule_priority_low_conf_beats_low_margin() {
        // Low confidence takes priority over low margin
        let decision = route(
            &default_config(),
            &RoutingInput {
                is_error: false,
                isa: &Isa::AArch64,
                confidence: 0.10,
                winner_score: 100,
                runner_up_score: 95,
            },
        );
        assert_eq!(decision.ambiguous_reason, Some(AmbiguousReason::LowConf));
    }
}
