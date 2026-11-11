use decryptor_core::http_client::{detect_active_local_proxy, detect_active_local_proxy_fresh};
use decryptor_core::models::{
    LockedFileReport, ProcessBatchResult, ProcessOptions, SourceFileEntry, SourceKind,
    ALL_SUPPORTED_PROTOCOLS, SUPPORTED_FILE_EXTENSIONS,
};
use decryptor_core::pipeline::{
    is_supported_extension, load_app_state, normalize_path_key, process_batch_cancellable,
    record_folder_history, save_app_state, scan_folder_files, AppStateStore, FolderScanResult,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct ActiveJobState {
    cancel_flag: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

struct CancelGuard {
    slot: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    flag: Arc<AtomicBool>,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.slot.lock() {
            if let Some(ref cur) = *guard {
                if Arc::ptr_eq(cur, &self.flag) {
                    *guard = None;
                }
            }
        }
    }
}

fn install_cancel_flag(state: &ActiveJobState) -> (Arc<AtomicBool>, CancelGuard) {
    let flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut guard) = state.cancel_flag.lock() {
        if let Some(prev) = guard.replace(flag.clone()) {
            prev.store(true, Ordering::SeqCst);
        }
    }
    let guard = CancelGuard {
        slot: state.cancel_flag.clone(),
        flag: flag.clone(),
    };
    (flag, guard)
}

fn state_dir_for(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from(".decryptor_state"))
}

fn default_output_dir() -> String {
    if let Some(ud) = directories::UserDirs::new() {
        if let Some(dl) = ud.download_dir() {
            return dl.join("VPN-Decryptor-Outputs").to_string_lossy().to_string();
        }
    }
    r"G:\Ai project\VPN-Decryptor-Desktop\Outputs".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitialAppStatePayload {
    pub state: AppStateStore,
    pub detected_proxy: Option<String>,
    pub version: String,
    pub default_output_dir: String,
    pub all_protocols: Vec<String>,
    pub supported_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavePreferencesPayload {
    pub passwords: Vec<String>,
    pub options: ProcessOptions,
    pub theme: String,
    pub last_folder_path: String,
    pub include_subfolders: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropInspectResult {
    pub accepted: Vec<SourceFileEntry>,
    pub unsupported_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunBatchRequest {
    pub sources: Vec<SourceFileEntry>,
    pub subscription_urls_text: String,
    pub messy_text: String,
    pub batch_passwords: Vec<String>,
    pub options: ProcessOptions,
    pub tracked_folder_path: Option<String>,
    pub tracked_include_subfolders: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryLockedRequest {
    pub locked_files: Vec<LockedFileReport>,
    pub password: String,
    pub save_to_vault: bool,
    pub options: ProcessOptions,
    pub tracked_folder_path: Option<String>,
    pub tracked_include_subfolders: bool,
}

#[tauri::command]
async fn get_initial_state(app: AppHandle) -> Result<InitialAppStatePayload, String> {
    let sdir = state_dir_for(&app);
    let state = load_app_state(&sdir);
    let detected_proxy = tauri::async_runtime::spawn_blocking(detect_active_local_proxy)
        .await
        .ok()
        .flatten();
    Ok(InitialAppStatePayload {
        state,
        detected_proxy,
        version: decryptor_core::version().to_string(),
        default_output_dir: default_output_dir(),
        all_protocols: ALL_SUPPORTED_PROTOCOLS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        supported_extensions: SUPPORTED_FILE_EXTENSIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    })
}

#[tauri::command]
async fn detect_proxy_status() -> Option<String> {
    tauri::async_runtime::spawn_blocking(detect_active_local_proxy_fresh)
        .await
        .ok()
        .flatten()
}

#[tauri::command]
async fn save_user_preferences(
    app: AppHandle,
    payload: SavePreferencesPayload,
) -> Result<(), String> {
    let sdir = state_dir_for(&app);
    let mut state = load_app_state(&sdir);
    state.passwords = payload.passwords;
    state.options = payload.options;
    state.theme = payload.theme;
    state.last_folder_path = payload.last_folder_path;
    state.include_subfolders = payload.include_subfolders;
    save_app_state(&sdir, &state)
}

#[tauri::command]
async fn pick_folder(app: AppHandle, title: String) -> Result<Option<String>, String> {
    let app_clone = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app_clone.dialog().file().set_title(&title).blocking_pick_folder();
        match picked {
            Some(fp) => match fp.into_path() {
                Ok(p) => Ok(Some(p.to_string_lossy().to_string())),
                Err(e) => Err(format!("مسیر انتخاب‌شده معتبر نیست: {}", e)),
            },
            None => Ok(None),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn pick_files(app: AppHandle) -> Result<Vec<SourceFileEntry>, String> {
    let app_clone = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app_clone
            .dialog()
            .file()
            .set_title("انتخاب فایل‌های کانفیگ VPN")
            .add_filter("VPN Config Files", SUPPORTED_FILE_EXTENSIONS)
            .blocking_pick_files();
        let mut out = Vec::new();
        if let Some(paths) = picked {
            for fp in paths {
                if let Ok(p) = fp.into_path() {
                    let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file")
                        .to_string();
                    out.push(SourceFileEntry {
                        id: normalize_path_key(&p),
                        name,
                        path: Some(p.to_string_lossy().to_string()),
                        size,
                        kind: SourceKind::File,
                        raw_content: None,
                    });
                }
            }
        }
        Ok(out)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn inspect_dropped_paths(
    paths: Vec<String>,
    include_subfolders: bool,
) -> Result<DropInspectResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut accepted = Vec::new();
        let mut unsupported_names = Vec::new();
        for raw in paths {
            let p = PathBuf::from(&raw);
            if !p.exists() {
                continue;
            }
            if p.is_dir() {
                let scan = scan_folder_files(&p, include_subfolders, false, None)?;
                accepted.extend(scan.supported_files);
            } else if p.is_file() {
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let base_ext = ext.split(" (").next().unwrap_or(&ext);
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file")
                    .to_string();
                if is_supported_extension(base_ext) {
                    let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    accepted.push(SourceFileEntry {
                        id: normalize_path_key(&p),
                        name,
                        path: Some(p.to_string_lossy().to_string()),
                        size,
                        kind: SourceKind::File,
                        raw_content: None,
                    });
                } else {
                    unsupported_names.push(name);
                }
            }
        }
        Ok(DropInspectResult {
            accepted,
            unsupported_names,
        })
    })
    .await
    .map_err(|e| format!("خطا در بررسی فایل‌های رها شده: {}", e))?
}

#[tauri::command]
async fn scan_folder(
    app: AppHandle,
    folder_path: String,
    include_subfolders: bool,
    new_only: bool,
) -> Result<FolderScanResult, String> {
    let sdir = state_dir_for(&app);
    let mut state = load_app_state(&sdir);
    state.last_folder_path = folder_path.clone();
    state.include_subfolders = include_subfolders;
    let key = normalize_path_key(Path::new(&folder_path));
    let hist = state.imported_folders.get(&key).cloned();
    let folder_owned = folder_path.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        scan_folder_files(
            Path::new(&folder_owned),
            include_subfolders,
            new_only,
            hist.as_ref(),
        )
    })
    .await
    .map_err(|e| format!("خطا در اسکن پوشه: {}", e))??;
    let _ = save_app_state(&sdir, &state);
    Ok(res)
}

#[tauri::command]
async fn clear_folder_history(app: AppHandle, folder_path: String) -> Result<(), String> {
    let sdir = state_dir_for(&app);
    let mut state = load_app_state(&sdir);
    let key = normalize_path_key(Path::new(&folder_path));
    state.imported_folders.remove(&key);
    save_app_state(&sdir, &state)
}

#[tauri::command]
async fn cancel_decrypt_batch(job_state: tauri::State<'_, ActiveJobState>) -> Result<(), String> {
    if let Ok(guard) = job_state.cancel_flag.lock() {
        if let Some(ref flag) = *guard {
            flag.store(true, Ordering::SeqCst);
        }
    }
    Ok(())
}

#[tauri::command]
async fn run_decrypt_batch(
    app: AppHandle,
    job_state: tauri::State<'_, ActiveJobState>,
    req: RunBatchRequest,
) -> Result<ProcessBatchResult, String> {
    let sdir = state_dir_for(&app);
    let mut state = load_app_state(&sdir);
    state.options = req.options.clone();
    let saved_passwords = state.passwords.clone();

    let (cancel_flag, _guard) = install_cancel_flag(&job_state);

    let app_handle = app.clone();
    let cb = Arc::new(move |ev| {
        let _ = app_handle.emit("decrypt-progress", ev);
    });

    let result = process_batch_cancellable(
        &req.sources,
        &req.subscription_urls_text,
        &req.messy_text,
        &req.batch_passwords,
        &saved_passwords,
        &req.options,
        Some(cb),
        Some(cancel_flag),
    )
    .await?;

    record_folder_history(
        &mut state,
        req.tracked_folder_path.as_deref(),
        req.tracked_include_subfolders,
        &req.sources,
        &result,
    );
    let _ = save_app_state(&sdir, &state);
    Ok(result)
}

#[tauri::command]
async fn retry_locked_with_password(
    app: AppHandle,
    job_state: tauri::State<'_, ActiveJobState>,
    req: RetryLockedRequest,
) -> Result<ProcessBatchResult, String> {
    let sdir = state_dir_for(&app);
    let mut state = load_app_state(&sdir);
    let pw = req.password.trim().to_string();
    if req.save_to_vault && !pw.is_empty() && !state.passwords.contains(&pw) {
        state.passwords.push(pw.clone());
    }

    let (cancel_flag, _guard) = install_cancel_flag(&job_state);

    let retry_sources: Vec<SourceFileEntry> = req
        .locked_files
        .iter()
        .map(|lf| {
            let size = lf
                .file_path
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .map(|m| m.len())
                .unwrap_or(0);
            SourceFileEntry {
                id: lf.source_id.clone(),
                name: lf.file_name.clone(),
                path: lf.file_path.clone(),
                size,
                kind: SourceKind::File,
                raw_content: None,
            }
        })
        .collect();

    let app_handle = app.clone();
    let cb = Arc::new(move |ev| {
        let _ = app_handle.emit("decrypt-progress", ev);
    });

    let result = process_batch_cancellable(
        &retry_sources,
        "",
        "",
        &[pw],
        &state.passwords,
        &req.options,
        Some(cb),
        Some(cancel_flag),
    )
    .await?;

    record_folder_history(
        &mut state,
        req.tracked_folder_path.as_deref(),
        req.tracked_include_subfolders,
        &retry_sources,
        &result,
    );
    let _ = save_app_state(&sdir, &state);
    Ok(result)
}

#[tauri::command]
async fn open_folder_in_explorer(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("پوشه خروجی هنوز ایجاد نشده است: {}", path));
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("خطا در باز کردن پوشه: {}", e))?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(ActiveJobState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_initial_state,
            detect_proxy_status,
            save_user_preferences,
            pick_folder,
            pick_files,
            inspect_dropped_paths,
            scan_folder,
            clear_folder_history,
            cancel_decrypt_batch,
            run_decrypt_batch,
            retry_locked_with_password,
            open_folder_in_explorer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
