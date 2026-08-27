//! Olopa Command — the local operator workstation.
//!
//! Command is a **client**, never a supervisor. The agent is an independent
//! privileged daemon: quitting Command must never stop protection, so nothing
//! here owns the agent's lifetime. Every panel reads an artefact the agent or a
//! server already publishes.

mod agent;
mod diagnostics;
mod ebpf;
mod oil;
mod remote;
mod settings;
mod sim;

use serde_json::Value;
use std::sync::Mutex;
use tauri::State;

pub struct AppState {
    settings: Mutex<settings::Settings>,
}

impl AppState {
    /// Snapshot the settings instead of holding the lock across a request.
    fn settings(&self) -> settings::Settings {
        self.settings
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

// -- Settings ------------------------------------------------------------------

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> settings::Settings {
    state.settings()
}

#[tauri::command]
fn set_settings(
    state: State<'_, AppState>,
    next: settings::Settings,
) -> Result<settings::Settings, String> {
    settings::save(&next)?;
    if let Ok(mut guard) = state.settings.lock() {
        *guard = next.clone();
    }
    Ok(next)
}

#[tauri::command]
fn settings_location() -> String {
    settings::location()
}

// -- Agent ---------------------------------------------------------------------

#[tauri::command]
fn agent_status(state: State<'_, AppState>) -> agent::SnapshotReport<agent::AgentSnapshot> {
    agent::agent_status(&state.settings())
}

#[tauri::command]
fn secure_connect_status(
    state: State<'_, AppState>,
) -> agent::SnapshotReport<agent::SecureConnectHealth> {
    agent::secure_connect_status(&state.settings())
}

#[tauri::command]
fn host_facts() -> agent::HostFacts {
    agent::host_facts()
}

#[tauri::command]
fn agent_control(state: State<'_, AppState>, action: agent::AgentAction) -> agent::CommandOutcome {
    agent::control(&state.settings(), action)
}

#[tauri::command]
fn agent_cli_status(state: State<'_, AppState>) -> agent::CommandOutcome {
    agent::cli_status(&state.settings())
}

// -- eBPF ----------------------------------------------------------------------

#[tauri::command]
fn ebpf_inventory(state: State<'_, AppState>) -> ebpf::BpfInventory {
    let probes = agent::agent_status(&state.settings())
        .snapshot
        .map(|snapshot| snapshot.probes)
        .unwrap_or_default();
    ebpf::inventory(probes)
}

// -- OIL -----------------------------------------------------------------------

#[tauri::command]
fn oil_compile(source: String) -> oil::CompileReport {
    oil::compile_source(&source)
}

#[tauri::command]
fn oil_simulate(request: sim::SimulationRequest) -> sim::SimulationReport {
    sim::simulate(&request)
}

// -- Remote --------------------------------------------------------------------

#[tauri::command]
async fn http_request(
    state: State<'_, AppState>,
    target: remote::Target,
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<remote::HttpReply, String> {
    let settings = state.settings();
    Ok(remote::request(&settings, target, &method, &path, body).await)
}

// -- Diagnostics ---------------------------------------------------------------

#[tauri::command]
fn agent_logs(state: State<'_, AppState>, lines: usize) -> diagnostics::LogReply {
    diagnostics::agent_logs(&state.settings(), lines)
}

#[tauri::command]
fn export_diagnostics(state: State<'_, AppState>) -> Result<diagnostics::BundleReport, String> {
    diagnostics::export_bundle(&state.settings())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            settings: Mutex::new(settings::load()),
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            set_settings,
            settings_location,
            agent_status,
            secure_connect_status,
            host_facts,
            agent_control,
            agent_cli_status,
            ebpf_inventory,
            oil_compile,
            oil_simulate,
            http_request,
            agent_logs,
            export_diagnostics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Olopa Command");
}
