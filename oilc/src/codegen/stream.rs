// Generates a Tokio async stream operator for temporal/correlate rules.
// The operator is compiled directly into the olopa-agent binary.


// Generated operator structure:
//   - A stateful struct holding the sliding window buffers per stream
//   - An async fn process_event() called on every event
//   - A join engine that runs after each event to check for matches


pub fn emit_correlate_operator(rule: &MirRule) -> String {
    // ... generates code like:
    format!(r#"
/// Auto-generated stream operator: {name}
pub struct Op{id} {{
    window: Duration,
    // One sliding window buffer per correlated stream
    buf_0:  SlidingWindow<ProcessExecEvent>,
    buf_1:  SlidingWindow<CookieReadEvent>,
    buf_2:  SlidingWindow<NetworkConnEvent>,
    buf_3:  SlidingWindow<IdentitySessionEvent>,
}}


impl Op{id} {{
    pub fn new() -> Self {{
        Self {{
            window: Duration::from_secs({window_secs}),
            buf_0: SlidingWindow::new({window_secs}),
            buf_1: SlidingWindow::new({window_secs}),
            buf_2: SlidingWindow::new({window_secs}),
            buf_3: SlidingWindow::new({window_secs}),
        }}
    }}


    pub fn ingest(&mut self, event: &AnyEvent) -> Vec<Alert> {{
        // Route event to correct stream buffer
        match event {{
            AnyEvent::ProcessExec(e)  if {filter_0} => self.buf_0.push(e.clone()),
            AnyEvent::CookieRead(e)   if {filter_1} => self.buf_1.push(e.clone()),
            AnyEvent::NetworkConnect(e) if {filter_2} => self.buf_2.push(e.clone()),
            AnyEvent::Session(e)      if {filter_3} => self.buf_3.push(e.clone()),
            _ => return vec![],
        }}
        self.run_join()
    }}


    fn run_join(&self) -> Vec<Alert> {{
        let mut alerts = vec![];
        // Nested join — for each p in buf_0, find matching events in other buffers
        for p in self.buf_0.iter() {{
            for c in self.buf_1.iter().filter(|c| c.process_id == p.id) {{
                for n in self.buf_2.iter().filter(|n| n.process_id == p.id) {{
                    for s in self.buf_3.iter().filter(|s| s.user_id == p.user_id) {{
                        if {where_predicate} {{
                            let score = {score_expr};
                            alerts.push(self.build_alert(score, p, c, n, s));
                        }}
                    }}
                }}
            }}
        }}
        alerts
    }}
}}
"#, name=rule.name, id=rule.id, ...)
}


