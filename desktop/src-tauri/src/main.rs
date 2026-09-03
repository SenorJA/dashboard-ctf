#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! MIRV Desktop — Tauri shell that launches the Python backend as a sidecar,
//! health-checks it, then shows the WebView pointed at the bundled SPA.
//!
//! The canonical frontend (desktop/src) talks to the backend over
//! http://localhost:8000 / ws://localhost:8000 (wired in main.v2.js).

use std::time::{Duration, Instant};

use tauri::Manager;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// Backend sidecar name (+ optional target triple). Tauri resolves the name
/// to `binaries/mirv-backend[-<target-triple>][.exe]` automatically.
const SIDECAR: &str = "mirv-backend";
const BACKEND_URL: &str = "http://localhost:8000/api/health";
const BACKEND_READY_TIMEOUT: Duration = Duration::from_secs(45);

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let handle = app.handle().clone();
            tracing_command(&handle);

            // Launch the Python backend sidecar (`--tauri-mode`: no frontend
            // mount, no auto-reload, configurable port via MIRV_PORT/PORT).
            let sidecar = app.shell().sidecar(SIDECAR);
            let spawn_result = match sidecar {
                Ok(cmd) => cmd.args(["--tauri-mode"]).spawn(),
                Err(e) => {
                    eprintln!("[mirv] sidecar command build failed: {e}");
                    None
                }
            };

            if let Some(Ok((rx, _child))) = spawn_result {
                // Pipe backend stdout/stderr into the host console.
                spawn_sidecar_logger(handle.clone(), rx, SIDECAR.to_string());
                // Wait for the backend health endpoint before showing UI.
                let win_handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    wait_for_backend(&win_handle).await;
                });
            } else {
                eprintln!("[mirv] failed to spawn backend sidecar");
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Backend sidecar is killed automatically when the webview closes.
            if let tauri::WindowEvent::Destroyed = event {
                window.app_handle().exit(0);
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running MIRV Desktop");
}

/// Dev-only helper: log the sidecar spawn attempt (behind a no-op in release).
fn tracing_command(_handle: &tauri::AppHandle) {
    #[cfg(debug_assertions)]
    println!("[mirv] spawning sidecar: {SIDECAR} --tauri-mode");
}

/// Poll the backend health endpoint until it responds or the timeout elapses.
async fn wait_for_backend(handle: &tauri::AppHandle) {
    let start = Instant::now();
    let client = reqwest::Client::new();
    loop {
        if Instant::now().duration_since(start) > BACKEND_READY_TIMEOUT {
            eprintln!("[mirv] backend did not become ready in time");
            health_failed_dialog().await;
            return;
        }
        match client.get(BACKEND_URL).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("[mirv] backend ready on {BACKEND_URL}");
                if let Some(win) = handle.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
                return;
            }
            _ => tauri::async_runtime::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Show a best-effort OS error dialog if the backend can't start.
async fn health_failed_dialog() {
    // Keep it simple: the bundler only has the WebView; a native dialog plugin
    // (tauri-plugin-dialog) could be added later. Log for now.
    eprintln!("[mirv] backend unavailable — the SPA may not be functional");
}

/// Forward backend sidecar stdout/stderr to the host console.
fn spawn_sidecar_logger(handle: tauri::AppHandle, mut rx: tauri_plugin_shell::process::CommandEventReceiver, name: String) {
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    println!("[{name}] {}", String::from_utf8_lossy(&line).trim_end());
                }
                CommandEvent::Stderr(line) => {
                    eprintln!("[{name}:err] {}", String::from_utf8_lossy(&line).trim_end());
                }
                CommandEvent::Terminated(status) => {
                    eprintln!("[{name}] terminated: {status:?}");
                    // If the backend dies, close the app.
                    handle.exit(0);
                    return;
                }
                _ => {}
            }
        }
    });
}
