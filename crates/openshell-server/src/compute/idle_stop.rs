// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Idle stop: stop a sandbox whose terminal program has waited on the user
//! longer than its `idle_stop_after_seconds` setting.
//!
//! The supervisor owns the idle clock. It applies the effective setting to
//! the OSC 7501 program status it observes and proposes a stop once the wait
//! passes the timeout, then retracts the proposal as soon as input or a new
//! turn ends the wait. The replica that holds the sandbox's supervisor
//! session keeps the session's latest proposal in memory and stops the
//! sandbox through the ordinary stop path. Just before calling the driver,
//! after the `Stopping` write, it checks that the proposal still holds and
//! rolls the sandbox back to its previous state when it does not.

use std::time::{Duration, Instant};

use openshell_core::proto::{
    Sandbox, SandboxCondition, SandboxPhase, SupervisorWorkloadIdle, WorkloadProgramState,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use tonic::{Code, Status};
use tracing::{debug, info, warn};

use super::{ComputeRuntime, IdleStopInFlight, IdleStopSession, QuiesceCause, QuiesceOperation};
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};

pub use openshell_core::metadata::{IDLE_STOPPED_REASON, IDLE_STOPPING_REASON};

/// Durable marker that the in-flight stop was started by an idle proposal.
/// It survives gateway restarts and driver snapshots that rewrite conditions.
pub const IDLE_STOP_ANNOTATION: &str = "internal.openshell.ai/idle-stop";
pub const IDLE_STOPPING_MESSAGE: &str =
    "Sandbox stop requested after its program waited on the user past its idle timeout";
pub const IDLE_STOPPED_MESSAGE: &str = "Sandbox stopped after its program waited on the user past its idle timeout; connect to start it";
/// Reported app names are bounded by OSC 7501; bound them again here.
const MAX_APP: usize = 32;

/// The latest idle proposal of a supervisor session, held by the replica
/// that owns the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleProposal {
    pub session_id: String,
    pub instance_id: String,
    pub proposal_id: u64,
    pub state: WorkloadProgramState,
    /// The reported app, reduced to safe characters for logs.
    pub program: String,
    /// How long the program had waited when the supervisor sent it.
    pub idle_for: Duration,
    /// When the proposal reached the session handler.
    pub arrived: Instant,
}

impl IdleProposal {
    /// How long the program has waited by now, measured from the proposal.
    #[must_use]
    pub fn waited(&self) -> Duration {
        self.idle_for + self.arrived.elapsed()
    }
}

/// The reported app name, reduced to safe characters for logs.
#[must_use]
pub fn program_name(app: &str) -> String {
    let app: String = app
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "_.+-".contains(*c))
        .take(MAX_APP)
        .collect();
    if app.is_empty() {
        "program".to_string()
    } else {
        app
    }
}

/// The effective idle timeout for a raw setting value, or `None` when idle
/// stop is disabled.
#[must_use]
pub fn timeout_from_setting(seconds: Option<i64>) -> Option<Duration> {
    openshell_core::settings::idle_stop_timeout(seconds)
}

/// Whether `proposal` may stop `sandbox` under `timeout`: the sandbox is
/// `Ready`, the proposal comes from its running main-process instance, and
/// the program has waited at least the gateway's own timeout. The supervisor
/// may still hold an older, shorter setting.
#[must_use]
pub fn proposal_admits(sandbox: &Sandbox, proposal: &IdleProposal, timeout: Duration) -> bool {
    let Some(status) = sandbox.status.as_ref() else {
        return false;
    };
    status.phase == SandboxPhase::Ready as i32
        && (status.main_process_instance_id.is_empty()
            || status.main_process_instance_id == proposal.instance_id)
        && proposal.waited() >= timeout
}

/// The Ready condition of an idle-stopped sandbox. Driver snapshots of the
/// stopped runtime rewrite conditions, so the gateway reapplies it.
#[must_use]
pub fn idle_stopped_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: IDLE_STOPPED_REASON.to_string(),
        message: IDLE_STOPPED_MESSAGE.to_string(),
        transition_time: None,
    }
}

/// The Ready condition of a sandbox whose idle stop is in flight, reapplied
/// over driver snapshots so a connect can tell it apart from other stops.
#[must_use]
pub fn idle_stopping_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: IDLE_STOPPING_REASON.to_string(),
        message: IDLE_STOPPING_MESSAGE.to_string(),
        transition_time: None,
    }
}

/// Whether the stop in flight was started by an idle proposal.
#[must_use]
pub fn idle_stop_marked(sandbox: &Sandbox) -> bool {
    sandbox
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.annotations.contains_key(IDLE_STOP_ANNOTATION))
}

impl ComputeRuntime {
    /// Record an idle proposal or retraction from a supervisor session.
    ///
    /// A message from a session that is no longer current is dropped, and so
    /// is an older proposal from the current session. A proposal starts an
    /// idle stop on its own task unless one is already in flight; a
    /// retraction removes the proposal, which cancels a stop that has not yet
    /// reached the driver.
    pub fn record_workload_idle(
        &self,
        sandbox_id: &str,
        session_id: &str,
        instance_id: &str,
        proposes_idle: bool,
        message: &SupervisorWorkloadIdle,
    ) {
        if self.note_workload_idle(sandbox_id, session_id, instance_id, proposes_idle, message) {
            let runtime = self.clone();
            let sandbox_id = sandbox_id.to_string();
            tokio::spawn(async move { Box::pin(runtime.run_idle_stop(&sandbox_id)).await });
        }
    }

    /// Update the held proposal for [`Self::record_workload_idle`]. Returns
    /// whether a new proposal was recorded, which starts an idle stop.
    pub(super) fn note_workload_idle(
        &self,
        sandbox_id: &str,
        session_id: &str,
        instance_id: &str,
        proposes_idle: bool,
        message: &SupervisorWorkloadIdle,
    ) -> bool {
        if !proposes_idle
            || !self
                .supervisor_sessions
                .is_current_session(sandbox_id, session_id)
        {
            return false;
        }
        let mut proposals = self
            .idle_proposals
            .lock()
            .expect("idle proposal lock poisoned");
        let held = proposals
            .get(sandbox_id)
            .filter(|held| held.session_id == session_id);
        if message.idle {
            if held.is_some_and(|held| held.proposal_id >= message.proposal_id) {
                return false;
            }
            proposals.insert(
                sandbox_id.to_string(),
                IdleProposal {
                    session_id: session_id.to_string(),
                    instance_id: instance_id.to_string(),
                    proposal_id: message.proposal_id,
                    state: WorkloadProgramState::try_from(message.state)
                        .unwrap_or(WorkloadProgramState::Unspecified),
                    program: program_name(&message.app),
                    idle_for: message
                        .idle_for
                        .as_ref()
                        .and_then(|idle_for| openshell_core::time::duration_to_std(idle_for).ok())
                        .unwrap_or_default(),
                    arrived: Instant::now(),
                },
            );
            true
        } else {
            if held.is_some_and(|held| held.proposal_id <= message.proposal_id) {
                proposals.remove(sandbox_id);
            }
            false
        }
    }

    /// The current session's idle proposal for `sandbox_id`. A proposal from
    /// an ended session is dropped.
    pub(super) fn current_idle_proposal(&self, sandbox_id: &str) -> Option<IdleProposal> {
        let mut proposals = self
            .idle_proposals
            .lock()
            .expect("idle proposal lock poisoned");
        let proposal = proposals.get(sandbox_id)?.clone();
        if self
            .supervisor_sessions
            .is_current_session(sandbox_id, &proposal.session_id)
        {
            Some(proposal)
        } else {
            proposals.remove(sandbox_id);
            None
        }
    }

    /// Stop `sandbox_id` for the current idle proposal, logging the outcome.
    async fn run_idle_stop(&self, sandbox_id: &str) {
        match Box::pin(self.idle_stop_for_proposal(sandbox_id)).await {
            Ok(Some((stopped, proposal))) => info!(
                sandbox_id,
                sandbox_name = %stopped.object_name(),
                program = %proposal.program,
                state = ?proposal.state,
                idle_seconds = proposal.waited().as_secs(),
                "Stopped idle sandbox"
            ),
            Ok(None) => {}
            Err(status) if status.code() == Code::Aborted => debug!(
                sandbox_id,
                reason = %status.message(),
                "Abandoned an idle stop"
            ),
            Err(status) => warn!(
                sandbox_id,
                error = %status.message(),
                "Idle sandbox stop failed"
            ),
        }
    }

    /// Stop `sandbox_id` for the current session's idle proposal. Returns
    /// `None` when there is no proposal to act on, another idle stop is in
    /// flight, or the gateway declines it.
    pub(super) async fn idle_stop_for_proposal(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<(Sandbox, IdleProposal)>, Status> {
        let Some(_in_flight) = IdleStopInFlight::claim(&self.idle_stops_in_flight, sandbox_id)
        else {
            return Ok(None);
        };
        let Some(proposal) = self.current_idle_proposal(sandbox_id) else {
            return Ok(None);
        };
        let Some(sandbox) = self
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        else {
            return Ok(None);
        };
        if !self.idle_proposal_admitted(&sandbox, &proposal).await {
            debug!(sandbox_id, "Declined an idle stop proposal");
            return Ok(None);
        }
        let cause = QuiesceCause::Idle(IdleStopSession {
            session_id: proposal.session_id.clone(),
        });
        let stopped = Box::pin(self.quiesce_sandbox(
            QuiesceOperation::Stop,
            &cause,
            sandbox.object_workspace(),
            sandbox.object_name(),
        ))
        .await?;
        Ok(Some((stopped, proposal)))
    }

    /// Whether `proposal` may stop `sandbox` now: the gateway's effective
    /// timeout is enabled and reached, the sandbox is `Ready` on the
    /// proposing instance, and a fresh shared owner record names the
    /// proposing session.
    async fn idle_proposal_admitted(&self, sandbox: &Sandbox, proposal: &IdleProposal) -> bool {
        let Some(timeout) = self.idle_stop_timeout(sandbox).await else {
            return false;
        };
        proposal_admits(sandbox, proposal, timeout)
            && self
                .owned_by_session(sandbox.object_id(), &proposal.session_id)
                .await
    }

    /// The check before an idle `Stopping` write, run under the lifecycle
    /// lock: the proposing session's proposal still holds and still admits
    /// the stop.
    pub(super) async fn idle_stop_admitted(
        &self,
        sandbox: &Sandbox,
        cause: &IdleStopSession,
    ) -> bool {
        match self.current_idle_proposal(sandbox.object_id()) {
            Some(proposal) if proposal.session_id == cause.session_id => {
                self.idle_proposal_admitted(sandbox, &proposal).await
            }
            _ => false,
        }
    }

    /// The check after an idle `Stopping` write and before the driver call:
    /// no retraction or session change has arrived since. Everything the
    /// gateway received before this check counts, including a retraction
    /// sent while the write was in flight.
    pub(super) fn idle_stop_still_proposed(
        &self,
        sandbox_id: &str,
        cause: &IdleStopSession,
    ) -> bool {
        self.current_idle_proposal(sandbox_id)
            .is_some_and(|proposal| proposal.session_id == cause.session_id)
    }

    /// After an idle `Stopping` write and before the driver call: when a
    /// retraction or session change arrived since the check before the
    /// write, roll `transition` back to `previous` and abort. If the rollback
    /// loses a write race, the stop goes ahead as any in-flight stop would.
    pub(super) async fn undo_retracted_idle_stop(
        &self,
        cause: &IdleStopSession,
        previous: &Sandbox,
        transition: &Sandbox,
    ) -> Result<(), Status> {
        let sandbox_id = transition.object_id();
        if previous.phase() != SandboxPhase::Ready as i32
            || self.idle_stop_still_proposed(sandbox_id, cause)
        {
            return Ok(());
        }
        if self.restore_lifecycle_snapshot(transition, previous).await {
            info!(sandbox_id, "Rolled back an idle stop after new activity");
            return Err(Status::aborted(
                "sandbox became active during its idle stop; restored it",
            ));
        }
        warn!(
            sandbox_id,
            "Could not roll back an idle stop after new activity; stopping anyway"
        );
        Ok(())
    }

    /// Whether the shared owner record is fresh and names `session_id`.
    async fn owned_by_session(&self, sandbox_id: &str, session_id: &str) -> bool {
        SupervisorOwnerIndex::new(self.store.clone(), OWNER_TTL)
            .read(sandbox_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|owner| owner.is_fresh(OWNER_TTL) && owner.session_id == session_id)
    }

    /// The effective idle timeout for `sandbox`, or `None` when disabled.
    /// Gateway scope wins over sandbox scope.
    async fn idle_stop_timeout(&self, sandbox: &Sandbox) -> Option<Duration> {
        let global = crate::grpc::policy::global_idle_stop_after_seconds(&self.store)
            .await
            .ok()?;
        let setting = crate::grpc::policy::idle_stop_after_seconds(
            &self.store,
            global,
            sandbox.object_workspace(),
            sandbox.object_name(),
        )
        .await
        .ok()?;
        timeout_from_setting(setting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxStatus;

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn proposal(idle_for: u64) -> IdleProposal {
        IdleProposal {
            session_id: "session-1".into(),
            instance_id: "instance-1".into(),
            proposal_id: 1,
            state: WorkloadProgramState::Done,
            program: "claude-code".into(),
            idle_for: secs(idle_for),
            arrived: Instant::now(),
        }
    }

    fn ready_sandbox() -> Sandbox {
        Sandbox {
            status: Some(SandboxStatus {
                phase: SandboxPhase::Ready.into(),
                main_process_instance_id: "instance-1".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn program_names_are_reduced_to_safe_characters() {
        assert_eq!(program_name("bad app\u{1b}"), "badapp");
        assert_eq!(program_name(""), "program");
    }

    #[test]
    fn setting_values_map_to_timeouts() {
        assert_eq!(timeout_from_setting(None), None);
        assert_eq!(timeout_from_setting(Some(0)), None);
        assert_eq!(timeout_from_setting(Some(-5)), None);
        assert_eq!(timeout_from_setting(Some(600)), Some(secs(600)));
        assert_eq!(
            timeout_from_setting(Some(i64::MAX)),
            Some(secs(30 * 24 * 60 * 60))
        );
    }

    #[test]
    fn proposals_admit_only_ready_sandboxes_of_their_instance_past_the_timeout() {
        let sandbox = ready_sandbox();
        assert!(proposal_admits(&sandbox, &proposal(600), secs(600)));
        assert!(
            !proposal_admits(&sandbox, &proposal(300), secs(600)),
            "a supervisor on a shorter, older setting does not decide"
        );
        let mut other_instance = proposal(600);
        other_instance.instance_id = "instance-old".into();
        assert!(!proposal_admits(&sandbox, &other_instance, secs(600)));
        let mut stopping = ready_sandbox();
        stopping.status.as_mut().unwrap().phase = SandboxPhase::Stopping.into();
        assert!(!proposal_admits(&stopping, &proposal(600), secs(600)));
    }
}
