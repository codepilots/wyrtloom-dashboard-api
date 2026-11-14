//! Integration focus for the **execute** path added by the dashboard wiring
//! (Path B): `/api/tasks/:id/execute` runs an existing task through
//! `wyrtloom_core::pipeline::Pipeline::execute` against the shared board,
//! provider, and logger, then transitions it Done/Blocked/Stopped.
//!
//! This test drives the pipeline composably (the same objects the handler
//! builds), with a deterministic stub provider (no real LLM), and asserts the
//! full lifecycle: task ends up `Done` on the SQLite board with the result and
//! a call-log entry recorded. The HTTP auth handshake itself (client-signature
//! + session middleware) is unchanged existing code covered by the crate's
//! auth/session unit tests; this test locks in the net-new execution logic.

use std::sync::Arc;

use plugin_kanban_sqlite::SqliteKanbanBoard;
use plugin_logger_sqlite::SqliteCallLogger;
use wyrtloom_core::kanban::{KanbanBoard, TaskState};
use wyrtloom_core::escalation::{Escalation, EscalationError, HumanEscalation, HumanResponse};
use wyrtloom_core::logger::CallLogger;
use wyrtloom_core::pipeline::Pipeline;
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::provider::{
    ContentBlock, GenerationRequest, GenerationResponse, LlmProvider, ModelDescriptor, ProviderError,
    Usage,
};

/// A stub provider that returns a fixed "done" JSON the pipeline can parse.
#[derive(Clone)]
struct DoneProvider;

impl LlmProvider for DoneProvider {
    fn generate(&self, _req: GenerationRequest) -> Result<GenerationResponse, ProviderError> {
        Ok(GenerationResponse {
            content: vec![ContentBlock::Text(r#"{"status":"done","result":"4"}"#.into())],
            usage: Usage { input_tokens: 5, output_tokens: 3, cost: None },
        })
    }
    fn models(&self) -> Vec<ModelDescriptor> {
        vec![]
    }
}

/// Headless escalation: an agent block records the task as Blocked (never Try).
struct BlockEscalation;
impl HumanEscalation for BlockEscalation {
    fn escalate(&self, _e: Escalation) -> Result<HumanResponse, EscalationError> {
        Ok(HumanResponse::Chose("headless-block".into()))
    }
}

fn test_profile() -> TaskProfile {
    let mut p = TaskProfile::default_v01();
    p.model = "test-model".into();
    p
}

#[test]
fn pipeline_execute_runs_existing_task_to_done() {
    let board = Arc::new(SqliteKanbanBoard::in_memory().expect("board"));
    let logger = Arc::new(SqliteCallLogger::in_memory().expect("logger"));

    // Create the task exactly as the dashboard API does (host-created).
    let id = board
        .create(wyrtloom_core::kanban::NewTask {
            title: "arithmetic".into(),
            actor: "human:test".into(),
            depends_on: vec![],
        })
        .expect("create");

    let pipeline = Pipeline {
        kanban: board.clone(),
        provider: Arc::new(DoneProvider),
        logger: logger.clone(),
        escalation: Arc::new(BlockEscalation),
        profile: test_profile(),
        agent_id: "agent:wyrtloom-api".into(),
    };

    // The dashboard executes an EXISTING task (execute, not run).
    let outcome = pipeline.execute(id, "arithmetic", "What is 2+2?");
    match &outcome {
        wyrtloom_core::pipeline::PipelineOutcome::Done { task_id, result } => {
            assert_eq!(task_id, &id);
            assert_eq!(result, "4");
        }
        other => panic!("expected Done, got {other:?}"),
    }

    // The task is Done on the shared board.
    let task = board.get(id).expect("fetch");
    assert_eq!(task.state, TaskState::Done, "task should end Done");

    // A call-log entry was recorded.
    let logs = logger.all_logs().expect("logs");
    assert_eq!(logs.len(), 1, "one call logged");
    assert_eq!(logs[0].task, id);
    assert_eq!(logs[0].model, "test-model");
    assert_eq!(logs[0].usage.output_tokens, 3);
}

#[test]
fn pipeline_execute_records_blocked_task_when_agent_blocks() {
    // A provider that returns a "blocked" status exercises the headless
    // escalation path: the task ends Blocked, not Done.
    struct BlockingProvider;
    impl LlmProvider for BlockingProvider {
        fn generate(&self, _r: GenerationRequest) -> Result<GenerationResponse, ProviderError> {
            Ok(GenerationResponse {
                content: vec![ContentBlock::Text(
                    r#"{"status":"blocked","reason":"cannot comply"}"#.into(),
                )],
                usage: Usage { input_tokens: 4, output_tokens: 4, cost: None },
            })
        }
        fn models(&self) -> Vec<ModelDescriptor> {
            vec![]
        }
    }

    let board = Arc::new(SqliteKanbanBoard::in_memory().expect("board"));
    let logger = Arc::new(SqliteCallLogger::in_memory().expect("logger"));
    let id = board
        .create(wyrtloom_core::kanban::NewTask {
            title: "blocked-task".into(),
            actor: "human:test".into(),
            depends_on: vec![],
        })
        .expect("create");

    let pipeline = Pipeline {
        kanban: board.clone(),
        provider: Arc::new(BlockingProvider),
        logger: logger.clone(),
        escalation: Arc::new(BlockEscalation),
        profile: test_profile(),
        agent_id: "agent:wyrtloom-api".into(),
    };

    let outcome = pipeline.execute(id, "blocked-task", "do the thing");
    let blocked_ok = matches!(
        &outcome,
        wyrtloom_core::pipeline::PipelineOutcome::Blocked { reason, .. }
            if reason.contains("cannot comply")
    );
    assert!(blocked_ok, "expected Blocked, got {outcome:?}");

    // The board reflects Blocked.
    let task = board.get(id).expect("fetch");
    assert_eq!(task.state, TaskState::Blocked, "task should end Blocked");
    // The reason is surfaced on the task too.
    assert!(task.block_reason.map(|b| b.reason.clone()).unwrap_or_default().contains("cannot comply"));
}

#[test]
fn route_table_gates_execute_as_operator() {
    // The route table is the single source of truth for auth gating. Assert the
    // execute route exists and is gated at Operator — a human Operator is who
    // the SPA represents when triggering execution.
    let table = wyrtloom_dashboard_api::routes::route_table();
    let exec = table
        .iter()
        .find(|r| r.path == "/api/tasks/:id/execute")
        .expect("execute route registered");
    assert_eq!(exec.method, "POST");
    use wyrtloom_dashboard_api::auth::RequiredAuth;
    assert!(matches!(exec.auth, RequiredAuth::Role(wyrtloom_core::users::Role::Operator)));
    // And the startup assertion that every route is gated passes.
    wyrtloom_dashboard_api::routes::assert_all_routes_gated(&table);
}
