use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(mobile)]
use tauri::Manager;
#[cfg(desktop)]
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, Runtime,
};

mod commands;

static CONNECTED: AtomicBool = AtomicBool::new(false);

pub fn is_connected() -> bool {
    CONNECTED.load(Ordering::SeqCst)
}

pub fn set_connected(value: bool) {
    CONNECTED.store(value, Ordering::SeqCst);
}

#[cfg(desktop)]
fn create_tray_menu<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<Menu<R>> {
    let status = if is_connected() {
        "● Connected"
    } else {
        "○ Disconnected"
    };

    let status_item = MenuItem::with_id(app, "status", status, false, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        if is_connected() {
            "Disconnect"
        } else {
            "Connect"
        },
        true,
        None::<&str>,
    )?;
    let separator = MenuItem::with_id(app, "sep", "─────────────", false, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Oxidize", true, None::<&str>)?;

    Menu::with_items(app, &[&status_item, &toggle, &separator, &show, &quit])
}

#[cfg(desktop)]
pub fn setup_tray<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    let menu = create_tray_menu(app)?;

    let _tray = TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .tooltip("Oxidize")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "toggle" => {
                let new_state = !is_connected();
                set_connected(new_state);

                // Update tray menu
                if let Ok(new_menu) = create_tray_menu(app) {
                    if let Some(tray) = app.tray_by_id("main") {
                        let _ = tray.set_menu(Some(new_menu));
                    }
                }

                // Emit event to frontend
                let _ = app.emit("connection-changed", new_state);

                // Note: Actual connection is handled via commands::connect/disconnect
                // This tray toggle just updates UI state - frontend calls the real connect command
                tracing::info!("Connection toggled: {}", new_state);
            }
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
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
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .manage(commands::AppState::default());

    // Desktop-only plugins
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                Some(vec!["--minimized"]),
            ))
            .plugin(tauri_plugin_updater::Builder::new().build());
    }

    builder
        .setup(|_app| {
            #[cfg(desktop)]
            setup_tray(_app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::get_status,
            commands::get_regions,
            commands::get_closest_region,
            commands::get_next_server_for_region,
            commands::get_config,
            commands::set_config,
            commands::get_version,
            commands::ping_relay,
            commands::is_daemon_available,
            commands::daemon_get_status,
            commands::install_daemon,
            commands::uninstall_daemon,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
