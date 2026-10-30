use proto::v1::Phase;

use crate::ReconcilerError;

/// The instance lifecycle of section 6, plus the admission edges the diagram leaves out.
pub struct Lifecycle;

impl Lifecycle
{
    const DIAGRAM: &'static [(Phase, Phase)] = &[
        (Phase::Pending, Phase::Preparing),
        (Phase::Preparing, Phase::Booting),
        (Phase::Booting, Phase::Starting),
        (Phase::Starting, Phase::Running),
        (Phase::Running, Phase::Stopping),
        (Phase::Stopping, Phase::Stopped),
        (Phase::Stopped, Phase::Booting),
        (Phase::Stopped, Phase::Deleting),
        (Phase::Deleting, Phase::Deleted),
        (Phase::Preparing, Phase::Failed),
        (Phase::Booting, Phase::Failed),
        (Phase::Starting, Phase::Failed),
        (Phase::Running, Phase::Failed),
        (Phase::Failed, Phase::Booting),
        (Phase::Failed, Phase::Deleting),
    ];

    const ADMISSION: &'static [(Phase, Phase)] = &[
        (Phase::Pending, Phase::Rejected),
        (Phase::Stopped, Phase::Rejected),
        (Phase::Failed, Phase::Rejected),
        (Phase::Rejected, Phase::Pending),
        (Phase::Rejected, Phase::Deleting),
        (Phase::Pending, Phase::Deleting),
        (Phase::Deleted, Phase::Pending),
    ];

    pub fn allows(from: Phase, to: Phase) -> bool
    {
        Self::DIAGRAM
            .iter()
            .chain(Self::ADMISSION)
            .any(|edge| *edge == (from, to))
    }

    pub fn transition(from: Phase, to: Phase) -> Result<Phase, ReconcilerError>
    {
        if Self::allows(from, to)
        {
            Ok(to)
        }
        else
        {
            Err(ReconcilerError::InvalidTransition { from, to })
        }
    }

    pub fn diagram() -> &'static [(Phase, Phase)]
    {
        Self::DIAGRAM
    }

    pub fn phase_name(phase: Phase) -> &'static str
    {
        phase.as_str_name()
    }

    pub fn parse_phase(name: &str) -> Phase
    {
        match Phase::from_str_name(name)
        {
            Some(Phase::Unspecified) | None => Phase::Pending,
            Some(phase) => phase,
        }
    }

    pub fn holds_sandbox(phase: Phase) -> bool
    {
        matches!(
            phase,
            Phase::Booting | Phase::Starting | Phase::Running | Phase::Stopping
        )
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const ALL: [Phase; 11] = [
        Phase::Pending,
        Phase::Preparing,
        Phase::Booting,
        Phase::Starting,
        Phase::Running,
        Phase::Stopping,
        Phase::Stopped,
        Phase::Failed,
        Phase::Deleting,
        Phase::Deleted,
        Phase::Rejected,
    ];

    #[test]
    fn every_diagram_edge_is_allowed()
    {
        for (from, to) in Lifecycle::diagram()
        {
            assert_eq!(Lifecycle::transition(*from, *to).unwrap(), *to);
        }
        assert_eq!(Lifecycle::diagram().len(), 15);
    }

    #[test]
    fn invalid_transitions_are_refused()
    {
        let refused = [
            (Phase::Pending, Phase::Running),
            (Phase::Pending, Phase::Booting),
            (Phase::Preparing, Phase::Running),
            (Phase::Booting, Phase::Running),
            (Phase::Running, Phase::Stopped),
            (Phase::Running, Phase::Deleting),
            (Phase::Running, Phase::Booting),
            (Phase::Stopping, Phase::Running),
            (Phase::Stopping, Phase::Deleting),
            (Phase::Stopped, Phase::Running),
            (Phase::Stopped, Phase::Preparing),
            (Phase::Failed, Phase::Running),
            (Phase::Failed, Phase::Stopped),
            (Phase::Deleting, Phase::Stopped),
            (Phase::Deleted, Phase::Running),
            (Phase::Rejected, Phase::Running),
            (Phase::Booting, Phase::Stopping),
            (Phase::Starting, Phase::Stopping),
        ];
        for (from, to) in refused
        {
            assert!(
                matches!(
                    Lifecycle::transition(from, to),
                    Err(ReconcilerError::InvalidTransition { .. })
                ),
                "{from} -> {to} must be refused"
            );
        }
    }

    #[test]
    fn only_listed_edges_exist()
    {
        let allowed: usize = ALL
            .iter()
            .flat_map(|from| ALL.iter().map(move |to| (*from, *to)))
            .filter(|(from, to)| Lifecycle::allows(*from, *to))
            .count();
        assert_eq!(
            allowed,
            Lifecycle::DIAGRAM.len() + Lifecycle::ADMISSION.len()
        );
        for phase in ALL
        {
            assert!(!Lifecycle::allows(phase, phase));
        }
    }

    #[test]
    fn phase_names_round_trip()
    {
        for phase in ALL
        {
            assert_eq!(Lifecycle::parse_phase(Lifecycle::phase_name(phase)), phase);
        }
        assert_eq!(Lifecycle::parse_phase("Pending"), Phase::Pending);
        assert_eq!(Lifecycle::parse_phase("garbage"), Phase::Pending);
    }
}
