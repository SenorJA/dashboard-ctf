#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! MIRV Desktop — Tauri shell that launches the Python backend as a sidecar,
//! health-checks it, then shows the WebView pointed at the bundled SPA.
//!
//! The canonical frontend (desktop/src) talks to the backend over
//! http://localhost:8000 / ws://localhost:8000 (wired in main.v2.js).
//!
//! Desktop extras (Fase 4 quality-of-life):
//! - System tray: closing the window hides it to the tray instead of exiting;
//!   the tray menu (or left-click) restores the window, "Quit" exits for real.
//! - Auto-updater: on startup, checks GitHub Releases (latest.json) via
//!   tauri-plugin-updater and installs the signed update if available.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, WindowEvent,
};
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

/// Backend sidecar name (+ optional target triple). Tauri resolves the name
/// to `binaries/mirv-backend[-<target-triple>][.exe]` automatically.
const SIDECAR: &str = "mirv-backend";
const BACKEND_URL: &str = "http://localhost:8000/api/health";
const BACKEND_READY_TIMEOUT: Duration = Duration::from_secs(45);
const TRAY_ID: &str = "mirv-tray";
const MAIN_WIN: &str = "main";
const SPLASH_WIN: &str = "splash";
const ERROR_URL: &str = "tauri://localhost/error.html";

fn main() {
    // Shared "quitting for real" flag: the tray Quit item flips it so the
    // CloseRequested handler lets the window actually close instead of
    // hiding-to-tray.
    let quitting = Arc::new(AtomicBool::new(false));
    let quitting_tray = quitting.clone();
    let quitting_window = quitting.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            let handle = app.handle().clone();
            tracing_command(&handle);

            // Título base dinámico (incluye versión); se actualiza con el
            // estado del backend al conectar.
            refresh_status_title(&handle, "iniciando");

            setup_tray(handle.clone(), quitting_tray)?;
            setup_updater(&handle);

            // Launch the Python backend sidecar (`--tauri-mode`: no frontend
            // mount, no auto-reload, configurable port via MIRV_PORT/PORT).
            let sidecar = app.shell().sidecar(SIDECAR);
            let spawn_result = match sidecar {
                Ok(cmd) => match cmd.args(["--tauri-mode"]).spawn() {
                    Ok(tuple) => Some(tuple),
                    Err(spawn_err) => {
                        eprintln!("[mirv] sidecar spawn failed: {spawn_err}");
                        None
                    }
                },
                Err(e) => {
                    eprintln!("[mirv] sidecar command build failed: {e}");
                    None
                }
            };

            if let Some((rx, _child)) = spawn_result {
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
        .on_window_event(move |window, event| {
            // System tray UX: closing the MAIN window hides it to the tray
            // unless the user explicitly chose Quit from the tray menu.
            // (La ventana splash se destruye sin pasar por esta lógica.)
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    if window.label() == MAIN_WIN && !quitting_window.load(Ordering::Relaxed) {
                        let _ = window.hide();
                        api.prevent_close();
                    }
                }
                // Hard-destroy path (real quit) → kill the app (sidecar dies
                // automatically when the process exits). Solo la main: la
                // splash se destruye al arrancar sin matar la app.
                WindowEvent::Destroyed => {
                    if window.label() == MAIN_WIN {
                        window.app_handle().exit(0);
                    }
                }
                _ => {}
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

/// Build the system-tray icon + menu (Show / Quit). Left-click on the icon
/// restores the main window; the menu is shown on right-click.
fn setup_tray(app: tauri::AppHandle, quitting: Arc<AtomicBool>) -> tauri::Result<()> {
    let show = MenuItem::with_id(&app, "show", "Show MIRV", true, None::<&str>)?;
    let quit = MenuItem::with_id(&app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(&app, &[&show, &quit])?;

    let icon = app
        .default_window_icon()
        .cloned()
        .unwrap_or_else(|| {
            tauri::image::Image::from_bytes(include_bytes!("../icons/32x32.png"))
                .expect("valid embedded tray icon")
        });

    let _tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("MIRV — Multi-platform Incident Response & Vulnerabilities")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app_handle, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app_handle.get_webview_window(MAIN_WIN) {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                quitting.store(true, Ordering::Relaxed);
                app_handle.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app_handle = tray.app_handle();
                if let Some(window) = app_handle.get_webview_window(MAIN_WIN) {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(&app)?;

    Ok(())
}

/// Fire-and-forget updater check: download + install on startup, then restart
/// into the fresh version. No-op/quiet when there is nothing to update or the
/// GitHub endpoint is unreachable.
fn setup_updater(app: &tauri::AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let updater = match handle.updater() {
            Ok(updater) => updater,
            Err(e) => {
                eprintln!("[mirv] updater unavailable: {e}");
                return;
            }
        };
        match updater.check().await {
            Ok(Some(update)) => {
                println!("[mirv] update available: v{}", update.version);
                let mut downloaded = 0usize;
                match update
                    .download_and_install(
                        |received, total| {
                            downloaded = received;
                            println!(
                                "[mirv] downloading {}/{} bytes",
                                received,
                                total.unwrap_or(0)
                            );
                        },
                        || {},
                    )
                    .await
                {
                    Ok(_) => {
                        println!("[mirv] update installed ({downloaded} bytes) — restarting");
                        handle.restart();
                    }
                    Err(e) => eprintln!("[mirv] update install failed: {e}"),
                }
            }
            Ok(None) => println!("[mirv] no updates available"),
            Err(e) => println!("[mirv] updater check failed (will retry next launch): {e}"),
        }
    });
}

/// Poll the backend health endpoint until it responds or the timeout elapses.
/// On success the splash closes and the main window shows (título dinámico);
/// on timeout the main window loads the bundled error page instead.
async fn wait_for_backend(handle: &tauri::AppHandle) {
    let start = Instant::now();
    let client = reqwest::Client::new();
    loop {
        if Instant::now().duration_since(start) > BACKEND_READY_TIMEOUT {
            eprintln!("[mirv] backend did not become ready in time");
            show_error_page(handle).await;
            return;
        }
        match client.get(BACKEND_URL).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("[mirv] backend ready on {BACKEND_URL}");
                refresh_status_title(handle, "backend conectado");
                show_main_and_close_splash(handle);
                return;
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Dynamic window title with version + backend status.
fn refresh_status_title(app: &tauri::AppHandle, status: &str) {
    let version = app.package_info().version.to_string();
    if let Some(win) = app.get_webview_window(MAIN_WIN) {
        let _ = win.set_title(&format!("M.I.R.V. v{version} — {status}"));
    }
}

/// Reveal the main window and drop the splash once the backend is ready.
fn show_main_and_close_splash(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN_WIN) {
        let _ = win.show();
        let _ = win.set_focus();
    }
    dismiss_splash(app);
}

/// Best-effort error page: if the backend can't start, navigate the main
/// window to the bundled error.html and show it (the splash closes).
async fn show_error_page(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN_WIN) {
        if let Ok(url) = tauri::Url::parse(ERROR_URL) {
            let _ = win.navigate(url);
        }
        refresh_status_title(app, "backend caido");
        let _ = win.show();
        let _ = win.set_focus();
    }
    dismiss_splash(app);
}

fn dismiss_splash(app: &tauri::AppHandle) {
    if let Some(splash) = app.get_webview_window(SPLASH_WIN) {
        let _ = splash.destroy();
    }
}

/// Forward backend sidecar stdout/stderr to the host console.
fn spawn_sidecar_logger(handle: tauri::AppHandle, mut rx: tauri::async_runtime::Receiver<CommandEvent>, name: String) {
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