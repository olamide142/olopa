//! Central Multi-Agent and Multi-Source Correlation Subsystem.
//!
//! Provides near real-time stream correlation, sliding-window multi-event joins,
//! central novelty state tracking, and central fact stores for `app/ingest_server`.

pub mod alerts;
pub mod engine;
pub mod event;
pub mod intel;
pub mod ir;
pub mod state;
pub mod value;
pub mod vectorized;
pub mod window;

pub use alerts::{AlertRingBuffer, CorrelatedAlert, CorrelatedEventSnippet};
pub use engine::{CompiledRule, CorrelationEngine, CorrelationStats};
pub use event::{EventFamily, OwnedEvent, UnifiedEventRef};
pub use intel::{CentralFact, CentralIntelStore};
pub use ir::{
    parse_runtime_program, RuntimeAction, RuntimeCallable, RuntimeDuration, RuntimeDurationUnit,
    RuntimeEmit, RuntimeExpr, RuntimeField, RuntimeJoin, RuntimeLet, RuntimeProgram,
    RuntimeRespondBranch, RuntimeRespondPlan, RuntimeRule, RuntimeRuleClass, RuntimeScore,
    RuntimeScoreModifier, RuntimeSource,
};
pub use state::{CentralCallableState, HostBaseline, UserBaseline};
pub use value::{glob_match, Value};
pub use vectorized::{BatchColumnIndex, FilterMask};
pub use window::SlidingWindowIndex;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::telemetry::{
        AgentHeartbeat, DbQueryEvent, FileEvent, IngestBatchRequest, NetEvent, ProcessExecEvent,
    };

    fn make_test_batch() -> IngestBatchRequest {
        IngestBatchRequest {
            tenant_id: "tenant-prod".to_string(),
            host_id: "host-alpha".to_string(),
            schema_version: 2,
            batch_id: Some("batch-001".to_string()),
            process_exec_events: vec![
                ProcessExecEvent {
                    pid: 1001,
                    tgid: 1001,
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    comm: "bash".to_string(),
                    filename: "/bin/bash".to_string(),
                    attrs: HashMap::new(),
                },
                ProcessExecEvent {
                    pid: 2002,
                    tgid: 2002,
                    ppid: 1001,
                    uid: 1000,
                    gid: 1000,
                    comm: "python".to_string(),
                    filename: "/usr/bin/python3".to_string(),
                    attrs: HashMap::new(),
                },
            ],
            file_events: vec![
                FileEvent {
                    pid: 2002,
                    tgid: 2002,
                    uid: 1000,
                    gid: 1000,
                    comm: "python".to_string(),
                    operation: "read".to_string(),
                    path: "/etc/shadow".to_string(),
                    attrs: HashMap::new(),
                },
            ],
            net_events: vec![
                NetEvent {
                    pid: 2002,
                    tgid: 2002,
                    uid: 1000,
                    gid: 1000,
                    comm: "python".to_string(),
                    direction: "outbound".to_string(),
                    protocol: "tcp".to_string(),
                    src_ip: Some("10.0.0.5".to_string()),
                    dst_ip: Some("198.51.100.44".to_string()),
                    src_port: Some(45123),
                    dst_port: Some(443),
                    attrs: {
                        let mut m = HashMap::new();
                        m.insert("bytes_out".to_string(), "150000".to_string());
                        m.insert("dest.domain".to_string(), "malicious-c2.example.com".to_string());
                        m
                    },
                },
            ],
            db_query_events: vec![
                DbQueryEvent {
                    pid: 3003,
                    tgid: 3003,
                    uid: 1000,
                    gid: 1000,
                    comm: "web-worker".to_string(),
                    db_engine: "postgresql".to_string(),
                    db_server: Some("pg.internal:5432".to_string()),
                    database: Some("customer_db".to_string()),
                    operation: "select".to_string(),
                    tables: vec!["users".to_string(), "credit_cards".to_string()],
                    statement_fingerprint: "select_users_dump".to_string(),
                    attrs: HashMap::new(),
                },
            ],
            agent_heartbeats: vec![
                AgentHeartbeat {
                    agent_version: "0.1.0".to_string(),
                    kernel_version: "6.8.0".to_string(),
                    events_read_total: 5000,
                    events_dropped_total: 0,
                    queue_depth: 12,
                    attrs: HashMap::new(),
                },
            ],
        }
    }

    #[test]
    fn single_event_rule_matches_and_scores() {
        let engine = CorrelationEngine::new();

        let rule = RuntimeRule {
            id: "detect_root_bash".to_string(),
            name: "Root interactive shell".to_string(),
            class: RuntimeRuleClass::HotPath,
            sources: vec![RuntimeSource {
                domain: "endpoint".to_string(),
                event: "process".to_string(),
                alias: Some("p".to_string()),
            }],
            predicates: vec![
                RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "comm".to_string() }),
                    rhs: Box::new(RuntimeExpr::Str { value: "bash".to_string() }),
                },
                RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "uid".to_string() }),
                    rhs: Box::new(RuntimeExpr::Int { value: 0 }),
                },
            ],
            joins: Vec::new(),
            window: None,
            require: Vec::new(),
            lets: vec![RuntimeLet {
                name: "is_root".to_string(),
                value: RuntimeExpr::Bool { value: true },
            }],
            score: RuntimeScore {
                base: 50,
                modifiers: vec![RuntimeScoreModifier {
                    delta: 30,
                    condition: Some(RuntimeExpr::Field { path: "is_root".to_string() }),
                }],
            },
            verify: Vec::new(),
            emit: vec![RuntimeEmit {
                fact_name: "host.root_shell".to_string(),
                args: vec![RuntimeExpr::Field { path: "host.id".to_string() }],
                expires: Some(RuntimeDuration {
                    value: 1,
                    unit: RuntimeDurationUnit::H,
                }),
            }],
            respond: RuntimeRespondPlan {
                branches: vec![RuntimeRespondBranch {
                    condition: Some(RuntimeExpr::Ge {
                        lhs: Box::new(RuntimeExpr::Field { path: "score".to_string() }),
                        rhs: Box::new(RuntimeExpr::Int { value: 80 }),
                    }),
                    actions: vec![RuntimeAction::Alert {
                        severity: "critical".to_string(),
                        message: Some("Root shell spawned on host".to_string()),
                    }],
                }],
            },
        };

        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![rule],
        });

        let batch = make_test_batch();
        let alerts = engine.evaluate_batch(&batch);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "detect_root_bash");
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[0].score, 80);
        assert_eq!(alerts[0].tenant_id, "tenant-prod");
        assert_eq!(alerts[0].host_id, "host-alpha");

        // Verify fact was stored
        assert!(engine.intel.has_fact("tenant-prod", "host.root_shell", Some("host-alpha")));
    }

    #[test]
    fn multi_source_correlation_joins_across_file_and_network() {
        let engine = CorrelationEngine::new();

        // OIL Rule: credential_access_followed_by_egress
        let rule = RuntimeRule {
            id: "credential_access_egress".to_string(),
            name: "Credential file access followed by egress".to_string(),
            class: RuntimeRuleClass::Temporal,
            sources: vec![
                RuntimeSource {
                    domain: "endpoint".to_string(),
                    event: "file".to_string(),
                    alias: Some("f".to_string()),
                },
                RuntimeSource {
                    domain: "network".to_string(),
                    event: "flow".to_string(),
                    alias: Some("n".to_string()),
                },
            ],
            predicates: vec![
                // f.path matches "/etc/shadow"
                RuntimeExpr::Matches {
                    lhs: Box::new(RuntimeExpr::Field { path: "f.path".to_string() }),
                    pattern: "/etc/shadow".to_string(),
                },
                // n.direction == "outbound"
                RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "n.direction".to_string() }),
                    rhs: Box::new(RuntimeExpr::Str { value: "outbound".to_string() }),
                },
            ],
            joins: vec![RuntimeJoin {
                left_alias: "f".to_string(),
                right_alias: "n".to_string(),
                on: Some(RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "f.pid".to_string() }),
                    rhs: Box::new(RuntimeExpr::Field { path: "n.pid".to_string() }),
                }),
            }],
            window: Some(RuntimeDuration {
                value: 10,
                unit: RuntimeDurationUnit::M,
            }),
            require: Vec::new(),
            lets: vec![
                RuntimeLet {
                    name: "high_exfil".to_string(),
                    value: RuntimeExpr::Gt {
                        lhs: Box::new(RuntimeExpr::Field { path: "n.bytes_out".to_string() }),
                        rhs: Box::new(RuntimeExpr::Int { value: 100_000 }),
                    },
                },
            ],
            score: RuntimeScore {
                base: 65,
                modifiers: vec![RuntimeScoreModifier {
                    delta: 20,
                    condition: Some(RuntimeExpr::Field { path: "high_exfil".to_string() }),
                }],
            },
            verify: Vec::new(),
            emit: vec![RuntimeEmit {
                fact_name: "host.credential_exfil".to_string(),
                args: vec![RuntimeExpr::Field { path: "host.id".to_string() }],
                expires: Some(RuntimeDuration {
                    value: 8,
                    unit: RuntimeDurationUnit::H,
                }),
            }],
            respond: RuntimeRespondPlan {
                branches: vec![RuntimeRespondBranch {
                    condition: Some(RuntimeExpr::Ge {
                        lhs: Box::new(RuntimeExpr::Field { path: "score".to_string() }),
                        rhs: Box::new(RuntimeExpr::Int { value: 85 }),
                    }),
                    actions: vec![
                        RuntimeAction::Alert {
                            severity: "critical".to_string(),
                            message: Some("High-volume credential exfiltration observed".to_string()),
                        },
                        RuntimeAction::Isolate {
                            isolate_kind: "host".to_string(),
                            target: "host-alpha".to_string(),
                        },
                    ],
                }],
            },
        };

        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![rule],
        });

        let batch = make_test_batch();
        let alerts = engine.evaluate_batch(&batch);

        assert!(!alerts.is_empty(), "Expected multi-source correlate alert");
        let alert = alerts.iter().find(|a| a.rule_id == "credential_access_egress").unwrap();
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.score, 85);
        assert_eq!(alert.matched_events.len(), 2);
        assert!(engine.intel.has_fact("tenant-prod", "host.credential_exfil", Some("host-alpha")));
    }

    #[test]
    fn cross_agent_novelty_and_intel_correlation() {
        let engine = CorrelationEngine::new();

        // Register a fact emitted on host-alpha
        engine.intel.emit_fact(
            "tenant-prod",
            "host-alpha",
            "host.compromised",
            vec!["host-alpha".to_string()],
            Some(3600_000),
        );

        // Rule: If query on another host targets credit card DB while host-alpha is compromised
        let rule = RuntimeRule {
            id: "db_exfil_during_campaign".to_string(),
            name: "Database dump during compromised campaign".to_string(),
            class: RuntimeRuleClass::Policy,
            sources: vec![RuntimeSource {
                domain: "database".to_string(),
                event: "query".to_string(),
                alias: Some("db".to_string()),
            }],
            predicates: vec![
                RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "db.database".to_string() }),
                    rhs: Box::new(RuntimeExpr::Str { value: "customer_db".to_string() }),
                },
                RuntimeExpr::Call {
                    name: "has_fact".to_string(),
                    args: vec![
                        RuntimeExpr::Str { value: "host.compromised".to_string() },
                        RuntimeExpr::Str { value: "host-alpha".to_string() },
                    ],
                },
            ],
            joins: Vec::new(),
            window: None,
            require: Vec::new(),
            lets: Vec::new(),
            score: RuntimeScore { base: 90, modifiers: Vec::new() },
            verify: Vec::new(),
            emit: Vec::new(),
            respond: RuntimeRespondPlan {
                branches: vec![RuntimeRespondBranch {
                    condition: None,
                    actions: vec![RuntimeAction::Alert {
                        severity: "critical".to_string(),
                        message: Some("Sensitive database query dump during active host compromise".to_string()),
                    }],
                }],
            },
        };

        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![rule],
        });

        // Batch from host-beta
        let mut batch_beta = make_test_batch();
        batch_beta.host_id = "host-beta".to_string();

        let alerts = engine.evaluate_batch(&batch_beta);
        let alert = alerts.iter().find(|a| a.rule_id == "db_exfil_during_campaign");
        assert!(alert.is_some(), "Expected cross-agent correlation match");
        assert_eq!(alert.unwrap().host_id, "host-beta");
    }

    #[test]
    fn vectorized_mask_operations() {
        let mut mask1 = FilterMask::all_clear(100);
        let mut mask2 = FilterMask::all_clear(100);

        mask1.set(10, true);
        mask1.set(20, true);
        mask1.set(30, true);

        mask2.set(20, true);
        mask2.set(40, true);

        mask1.and_with(&mask2);
        assert_eq!(mask1.count_ones(), 1);
        let indices: Vec<usize> = mask1.iter_indices().collect();
        assert_eq!(indices, vec![20]);
    }

    #[test]
    fn glob_matching_works() {
        assert!(glob_match("/etc/shadow", "/etc/shadow"));
        assert!(glob_match("/home/*/.ssh/id_rsa", "/home/ubuntu/.ssh/id_rsa"));
        assert!(glob_match("*.py", "main.py"));
        assert!(!glob_match("*.py", "main.rs"));
    }
}
