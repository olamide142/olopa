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
pub use event::{resolve_event_ts, EventFamily, OwnedEvent, UnifiedEventRef};
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
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::telemetry::{
        AgentHeartbeat, DbQueryEvent, FileEvent, IngestBatchRequest, NetEvent, ProcessExecEvent,
    };

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn root_bash_rule() -> RuntimeRule {
        RuntimeRule {
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
        }
    }

    fn make_test_batch() -> IngestBatchRequest {
        // Anchored near now: `resolve_event_ts` rejects stamps far outside batch
        // arrival time, so a hardcoded constant would age out of the window.
        let base_ts = now_unix_ms() - 60_000;

        IngestBatchRequest {
            tenant_id: "tenant-prod".to_string(),
            host_id: "host-alpha".to_string(),
            schema_version: 2,
            batch_id: Some("batch-001".to_string()),
            process_exec_events: vec![
                ProcessExecEvent {
                    ts_unix_ms: Some(base_ts),
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
                    ts_unix_ms: Some(base_ts + 1_000),
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
                    ts_unix_ms: Some(base_ts + 2_000),
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
                    ts_unix_ms: Some(base_ts + 3_000),
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
                    ts_unix_ms: Some(base_ts + 4_000),
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
                    ts_unix_ms: Some(base_ts + 5_000),
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

        let rule = root_bash_rule();
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

    #[test]
    fn event_time_prefers_agent_stamp_and_rejects_skew() {
        let arrival = now_unix_ms();

        // Agent stamp inside the trusted band wins over arrival time.
        let observed = arrival - 90_000;
        assert_eq!(resolve_event_ts(Some(observed), arrival), (observed, false));

        // A spooled event from hours ago is still a real observation.
        let spooled = arrival - 6 * 60 * 60 * 1_000;
        assert_eq!(resolve_event_ts(Some(spooled), arrival), (spooled, false));

        // Beyond the band it is a broken agent clock, not a late event.
        let ancient = arrival - 48 * 60 * 60 * 1_000;
        assert_eq!(resolve_event_ts(Some(ancient), arrival), (arrival, true));
        let future = arrival + 60 * 60 * 1_000;
        assert_eq!(resolve_event_ts(Some(future), arrival), (arrival, true));

        // Pre-schema-3 senders fall back to arrival time.
        assert_eq!(resolve_event_ts(None, arrival), (arrival, true));
    }

    #[test]
    fn correlation_uses_agent_event_time_not_arrival_time() {
        let batch = make_test_batch();
        let engine = CorrelationEngine::new();
        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![root_bash_rule()],
        });

        let alerts = engine.evaluate_batch(&batch);
        assert_eq!(alerts.len(), 1);

        // The matched snippet must carry the agent's observation time, which is
        // what a replay out of a persistent store would also see.
        let expected = batch.process_exec_events[0].ts_unix_ms.expect("fixture stamps ts");
        assert_eq!(alerts[0].matched_events[0].ts_unix_ms, expected);
        assert_eq!(engine.stats().events_ts_fallback, 0);
    }

    #[test]
    fn unstamped_events_fall_back_to_arrival_and_are_counted() {
        let mut batch = make_test_batch();
        for event in &mut batch.process_exec_events {
            event.ts_unix_ms = None;
        }

        let engine = CorrelationEngine::new();
        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![root_bash_rule()],
        });
        engine.evaluate_batch(&batch);

        // Both process events lost their stamp; the stat is what tells an
        // operator that a replay cannot reproduce this window.
        assert_eq!(engine.stats().events_ts_fallback, 2);
    }

    #[test]
    fn alert_ids_are_derived_from_content_not_evaluation_time() {
        let batch = make_test_batch();

        let evaluate = || {
            let engine = CorrelationEngine::new();
            engine.load_program(RuntimeProgram {
                version: 1,
                fields: Vec::new(),
                callables: Vec::new(),
                rules: vec![root_bash_rule()],
            });
            engine.evaluate_batch(&batch)
        };

        // Two independent engines standing in for the hot path and a later
        // replay of the same events must agree on the alert id.
        let first = evaluate();
        let second = evaluate();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].alert_id, second[0].alert_id);
        assert!(first[0].alert_id.starts_with("alt_detect_root_bash_"));

        // A different observation of the same rule is a different alert.
        let mut other_batch = make_test_batch();
        other_batch.process_exec_events[0].pid = 4242;
        let engine = CorrelationEngine::new();
        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![root_bash_rule()],
        });
        let other = engine.evaluate_batch(&other_batch);
        assert_eq!(other.len(), 1);
        assert_ne!(first[0].alert_id, other[0].alert_id);
    }

    #[test]
    fn multi_source_alert_ids_ignore_alias_iteration_order() {
        // The multi-source path collects matches into a map, so the id must not
        // depend on which alias happens to be visited first.
        let forward = CorrelatedAlert::derive_id(
            "rule_x",
            "tenant-prod",
            ["file|host-a|100|1|read|/etc/shadow".to_string(), "net|host-a|200|1|tcp".to_string()],
        );
        let reversed = CorrelatedAlert::derive_id(
            "rule_x",
            "tenant-prod",
            ["net|host-a|200|1|tcp".to_string(), "file|host-a|100|1|read|/etc/shadow".to_string()],
        );
        assert_eq!(forward, reversed);

        // Tenant is part of the identity: same events, different tenant.
        let other_tenant = CorrelatedAlert::derive_id(
            "rule_x",
            "tenant-dev",
            ["file|host-a|100|1|read|/etc/shadow".to_string(), "net|host-a|200|1|tcp".to_string()],
        );
        assert_ne!(forward, other_tenant);
    }

    fn empty_batch(host_id: &str) -> IngestBatchRequest {
        IngestBatchRequest {
            tenant_id: "tenant-prod".to_string(),
            host_id: host_id.to_string(),
            schema_version: 3,
            batch_id: None,
            process_exec_events: Vec::new(),
            file_events: Vec::new(),
            net_events: Vec::new(),
            db_query_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    fn shadow_read(pid: u32) -> FileEvent {
        FileEvent {
            ts_unix_ms: Some(now_unix_ms() - 60_000),
            pid,
            tgid: pid,
            uid: 1000,
            gid: 1000,
            comm: "python".to_string(),
            operation: "read".to_string(),
            path: "/etc/shadow".to_string(),
            attrs: HashMap::new(),
        }
    }

    fn outbound_flow(pid: u32) -> NetEvent {
        NetEvent {
            ts_unix_ms: Some(now_unix_ms() - 30_000),
            pid,
            tgid: pid,
            uid: 1000,
            gid: 1000,
            comm: "python".to_string(),
            direction: "outbound".to_string(),
            protocol: "tcp".to_string(),
            src_ip: Some("10.0.0.5".to_string()),
            dst_ip: Some("198.51.100.44".to_string()),
            src_port: Some(45123),
            dst_port: Some(443),
            attrs: HashMap::new(),
        }
    }

    fn python_exec(pid: u32) -> ProcessExecEvent {
        ProcessExecEvent {
            ts_unix_ms: Some(now_unix_ms() - 60_000),
            pid,
            tgid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "python".to_string(),
            filename: "/usr/bin/python3".to_string(),
            attrs: HashMap::new(),
        }
    }

    /// Two-source rule that alerts on any match, so tests assert on whether the
    /// join happened rather than on scoring.
    fn always_alerting_rule(
        id: &str,
        sources: Vec<RuntimeSource>,
        predicates: Vec<RuntimeExpr>,
        joins: Vec<RuntimeJoin>,
    ) -> RuntimeRule {
        RuntimeRule {
            id: id.to_string(),
            name: id.to_string(),
            class: RuntimeRuleClass::Temporal,
            sources,
            predicates,
            joins,
            window: Some(RuntimeDuration {
                value: 10,
                unit: RuntimeDurationUnit::M,
            }),
            require: Vec::new(),
            lets: Vec::new(),
            score: RuntimeScore {
                base: 90,
                modifiers: Vec::new(),
            },
            verify: Vec::new(),
            emit: Vec::new(),
            respond: RuntimeRespondPlan {
                branches: vec![RuntimeRespondBranch {
                    condition: None,
                    actions: vec![RuntimeAction::Alert {
                        severity: "high".to_string(),
                        message: Some("matched".to_string()),
                    }],
                }],
            },
        }
    }

    fn load(engine: &CorrelationEngine, rule: RuntimeRule) {
        engine.load_program(RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![rule],
        });
    }

    #[test]
    fn same_pid_on_two_hosts_does_not_produce_a_false_join() {
        // No declared join, so the engine falls back to keying on pid. Two
        // unrelated processes that happen to share pid 1001 on different
        // machines must not be correlated into one alert.
        let rule = always_alerting_rule(
            "shadow_then_egress",
            vec![
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
            vec![RuntimeExpr::Eq {
                lhs: Box::new(RuntimeExpr::Field { path: "n.direction".to_string() }),
                rhs: Box::new(RuntimeExpr::Str { value: "outbound".to_string() }),
            }],
            Vec::new(),
        );

        let engine = CorrelationEngine::new();
        load(&engine, rule);

        let mut alpha = empty_batch("host-alpha");
        alpha.file_events.push(shadow_read(1001));
        assert!(engine.evaluate_batch(&alpha).is_empty());

        let mut beta = empty_batch("host-beta");
        beta.net_events.push(outbound_flow(1001));
        let alerts = engine.evaluate_batch(&beta);

        assert!(
            alerts.is_empty(),
            "pid 1001 on two hosts must not join: {alerts:?}"
        );
    }

    #[test]
    fn same_pid_on_one_host_still_joins() {
        let rule = always_alerting_rule(
            "shadow_then_egress",
            vec![
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
            vec![RuntimeExpr::Eq {
                lhs: Box::new(RuntimeExpr::Field { path: "n.direction".to_string() }),
                rhs: Box::new(RuntimeExpr::Str { value: "outbound".to_string() }),
            }],
            Vec::new(),
        );

        let engine = CorrelationEngine::new();
        load(&engine, rule);

        let mut first = empty_batch("host-alpha");
        first.file_events.push(shadow_read(1001));
        assert!(engine.evaluate_batch(&first).is_empty());

        let mut second = empty_batch("host-alpha");
        second.net_events.push(outbound_flow(1001));
        let alerts = engine.evaluate_batch(&second);

        assert_eq!(alerts.len(), 1, "same host and pid should still correlate");
        assert_eq!(alerts[0].host_id, "host-alpha");
    }

    #[test]
    fn declared_join_correlates_across_agents() {
        // The rule joins on a field two machines can genuinely share, so the
        // bucket is tenant-scoped and the match spans hosts. This is the case
        // the engine advertises as multi-agent correlation.
        let rule = always_alerting_rule(
            "same_binary_fleet_wide",
            vec![
                RuntimeSource {
                    domain: "endpoint".to_string(),
                    event: "process".to_string(),
                    alias: Some("p".to_string()),
                },
                RuntimeSource {
                    domain: "network".to_string(),
                    event: "flow".to_string(),
                    alias: Some("n".to_string()),
                },
            ],
            vec![RuntimeExpr::Eq {
                lhs: Box::new(RuntimeExpr::Field { path: "n.direction".to_string() }),
                rhs: Box::new(RuntimeExpr::Str { value: "outbound".to_string() }),
            }],
            vec![RuntimeJoin {
                left_alias: "p".to_string(),
                right_alias: "n".to_string(),
                on: Some(RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field { path: "p.comm".to_string() }),
                    rhs: Box::new(RuntimeExpr::Field { path: "n.comm".to_string() }),
                }),
            }],
        );

        let engine = CorrelationEngine::new();
        load(&engine, rule);

        // Deliberately different pids: the join is on comm, not pid.
        let mut alpha = empty_batch("host-alpha");
        alpha.process_exec_events.push(python_exec(1001));
        assert!(engine.evaluate_batch(&alpha).is_empty());

        let mut beta = empty_batch("host-beta");
        beta.net_events.push(outbound_flow(7777));
        let alerts = engine.evaluate_batch(&beta);

        assert_eq!(alerts.len(), 1, "declared join should correlate across hosts");
        let hosts: Vec<&str> = alerts[0]
            .matched_events
            .iter()
            .map(|e| e.host_id.as_str())
            .collect();
        assert!(hosts.contains(&"host-alpha") && hosts.contains(&"host-beta"));
    }

    #[test]
    fn join_terms_come_from_field_equalities_only() {
        let field = |path: &str| RuntimeExpr::Field { path: path.to_string() };

        let rule = always_alerting_rule(
            "compound",
            Vec::new(),
            Vec::new(),
            vec![RuntimeJoin {
                left_alias: "a".to_string(),
                right_alias: "b".to_string(),
                on: Some(RuntimeExpr::And {
                    lhs: Box::new(RuntimeExpr::And {
                        lhs: Box::new(RuntimeExpr::Eq {
                            lhs: Box::new(field("b.pid")),
                            rhs: Box::new(field("a.pid")),
                        }),
                        rhs: Box::new(RuntimeExpr::Eq {
                            lhs: Box::new(field("a.dst_ip")),
                            rhs: Box::new(field("b.dst_ip")),
                        }),
                    }),
                    // A comparison against a literal is a filter, not a join key.
                    rhs: Box::new(RuntimeExpr::Eq {
                        lhs: Box::new(field("a.uid")),
                        rhs: Box::new(RuntimeExpr::Int { value: 0 }),
                    }),
                }),
            }],
        );

        let compiled = CompiledRule::compile(rule);

        // Both terms kept, each normalized so the authored order cannot change
        // the key, and the set itself sorted for a stable key layout.
        assert_eq!(
            compiled.join_terms,
            vec![
                ("a.dst_ip".to_string(), "b.dst_ip".to_string()),
                ("a.pid".to_string(), "b.pid".to_string()),
            ]
        );
    }
}
