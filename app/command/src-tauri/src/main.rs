// Prevent a console window from opening alongside the app on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    olopa_command_lib::run()
}
