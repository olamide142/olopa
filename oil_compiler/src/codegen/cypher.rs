// Generates Memgraph AFTER COMMIT triggers for graph structural rules.
// Each rule produces: one trigger definition + one detection procedure.


pub fn emit_cypher_trigger(rule: &MirRule) -> CypherOutput {
    let trigger_name = sanitize_name(&rule.name);
    let proc_name = format!("detect.{}", trigger_name);


    // Determine which edge write should fire the trigger
    let trigger_pattern = emit_trigger_pattern(&rule.graph.patterns);


    // The Cypher MATCH query for structural detection
    let detection_query = emit_detection_query(&rule.graph.patterns, &rule.predicates);


    CypherOutput {
        // The AFTER COMMIT trigger — fires instantly on matching graph write
        trigger: format!(r#"
CREATE TRIGGER {trigger_name}_trigger
ON CREATE TO {trigger_pattern}
AFTER COMMIT
EXECUTE
    CALL {proc_name}(createdEdges) YIELD alert
    CALL olopa.emit_alert(alert);
        "#, trigger_name=trigger_name, trigger_pattern=trigger_pattern, proc_name=proc_name),


        // The detection procedure body
        procedure: format!(r#"
// Detection procedure: {name}
{detection_query}
RETURN
    {return_fields}
ORDER BY timestamp DESC
        "#, name=rule.name, detection_query=detection_query, ...),
    }
}


// ─── Example Cypher output for "webshell_chain" rule ─────────────────
// Trigger:
// CREATE TRIGGER webshell_chain_trigger
// ON CREATE TO ()-[:SPAWNED]->(:Process {comm: "bash"})
// AFTER COMMIT
// EXECUTE
//     CALL detect.webshell_chain(createdEdges) YIELD alert
//     CALL olopa.emit_alert(alert);
//
// Procedure:
// MATCH path = (web:Process)-[:SPAWNED*1..3]->(shell:Process)
//              -[:CONNECTED_TO]->(ext:NetworkEndpoint)
// WHERE web.comm IN ["nginx","apache2","httpd","gunicorn"]
//   AND shell.comm IN ["bash","sh","zsh","python3"]
//   AND NOT ext.is_internal
// RETURN web.host_id, shell.comm, ext.ip, length(path) AS depth
// ORDER BY ext.threat_intel_score DESC
