use decryptor_core::models::{
    OutputFormatSettings, OutputScopeSettings, ProcessOptions, ProtocolSplitSettings, ProxyMode,
    SourceFileEntry, SourceKind, ALL_SUPPORTED_PROTOCOLS,
};
use decryptor_core::pipeline::{
    load_app_state, process_batch, record_folder_history, save_app_state, scan_folder_files,
};
use std::path::PathBuf;
use std::sync::Arc;

fn print_usage() {
    println!("VPN Decryptor CLI v{}", decryptor_core::version());
    println!("Usage:");
    println!("  decryptor-cli --dir <INPUT_DIR> --out <OUT_DIR> [OPTIONS]");
    println!("Options:");
    println!("  --dir <PATH>          Scan folder for supported VPN configs");
    println!("  --file <PATH>         Add a single file (repeatable)");
    println!("  --sub <URL>           Add a subscription URL (repeatable)");
    println!("  --out <PATH>          Output folder (default: ./Outputs/CLI_Run)");
    println!("  --pass <STR>          Password to test / vault (repeatable)");
    println!("  --state-dir <PATH>    App state/history JSON directory");
    println!("  --subfolders          Recurse into subdirectories");
    println!("  --new-only            Only import files not previously processed in state-dir");
    println!("  --per-source          Enable Per_Source folders");
    println!("  --no-mix              Disable Mix_All folder");
    println!("  --by-protocol         Enable By_Protocol split files");
    println!("  --all-formats         Enable Xray, Xray-Base64, Sing-box, Mihomo, Companions");
    println!("  --json-summary        Print full JSON summary at end");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }

    let mut input_dir: Option<PathBuf> = None;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut subs: Vec<String> = Vec::new();
    let mut out_dir = PathBuf::from("Outputs").join("CLI_Run");
    let mut passwords: Vec<String> = Vec::new();
    let mut state_dir: Option<PathBuf> = None;
    let mut subfolders = false;
    let mut new_only = false;
    let mut per_source = false;
    let mut no_mix = false;
    let mut by_protocol = false;
    let mut all_formats = false;
    let mut json_summary = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" if i + 1 < args.len() => {
                input_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--file" if i + 1 < args.len() => {
                files.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--sub" if i + 1 < args.len() => {
                subs.push(args[i + 1].clone());
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--pass" if i + 1 < args.len() => {
                passwords.push(args[i + 1].clone());
                i += 2;
            }
            "--state-dir" if i + 1 < args.len() => {
                state_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--subfolders" => {
                subfolders = true;
                i += 1;
            }
            "--new-only" => {
                new_only = true;
                i += 1;
            }
            "--per-source" => {
                per_source = true;
                i += 1;
            }
            "--no-mix" => {
                no_mix = true;
                i += 1;
            }
            "--by-protocol" => {
                by_protocol = true;
                i += 1;
            }
            "--all-formats" => {
                all_formats = true;
                i += 1;
            }
            "--json-summary" => {
                json_summary = true;
                i += 1;
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
    }

    let mut state = state_dir
        .as_deref()
        .map(load_app_state)
        .unwrap_or_default();

    let mut sources: Vec<SourceFileEntry> = Vec::new();
    let mut tracked_folder_str: Option<String> = None;

    if let Some(ref dir) = input_dir {
        tracked_folder_str = Some(dir.to_string_lossy().to_string());
        let key = decryptor_core::pipeline::normalize_path_key(dir);
        let prev_hist = state.imported_folders.get(&key);
        match scan_folder_files(dir, subfolders, new_only, prev_hist) {
            Ok(scan) => {
                eprintln!(
                    "Scanned {}: total={}, supported={}, unsupported={}, skipped_new_only={}",
                    scan.folder_path,
                    scan.total_files_seen,
                    scan.supported_files.len(),
                    scan.unsupported_count,
                    scan.skipped_already_imported
                );
                sources.extend(scan.supported_files);
            }
            Err(e) => {
                eprintln!("Folder scan error: {}", e);
                std::process::exit(1);
            }
        }
    }

    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let size = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
        sources.push(SourceFileEntry {
            id: decryptor_core::pipeline::normalize_path_key(&f),
            name,
            path: Some(f.to_string_lossy().to_string()),
            size,
            kind: SourceKind::File,
            raw_content: None,
        });
    }

    let options = ProcessOptions {
        filter_duplicates: true,
        filter_broken: true,
        ignore_expired: true,
        limit_max_configs: false,
        max_configs_count: 500,
        allowed_protocols: ALL_SUPPORTED_PROTOCOLS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        output_scope: OutputScopeSettings {
            mix_all: !no_mix,
            per_source,
        },
        output_formats: OutputFormatSettings {
            xray: true,
            xray_base64: all_formats,
            singbox: true,
            mihomo: true,
            companions: true,
        },
        protocol_split: ProtocolSplitSettings {
            all_protocols: true,
            by_protocol,
        },
        output_dir: out_dir.to_string_lossy().to_string(),
        move_decrypted_to_trash: false,
        proxy_mode: ProxyMode::AutoDetect,
        custom_proxy_url: String::new(),
    };

    let subs_text = subs.join("\n");
    let progress = Arc::new(|ev: decryptor_core::models::ProgressEventPayload| {
        if ev.current == ev.total || ev.current % 25 == 0 {
            eprintln!("[{}%] {}/{} {}", ev.percent, ev.current, ev.total, ev.current_item);
        }
    });

    match process_batch(
        &sources,
        &subs_text,
        "",
        &passwords,
        &state.passwords,
        &options,
        Some(progress),
    )
    .await
    {
        Ok(res) => {
            if let (Some(ref sdir), Some(ref folder_str)) = (&state_dir, &tracked_folder_str) {
                record_folder_history(&mut state, Some(folder_str.as_str()), subfolders, &sources, &res);
                let _ = save_app_state(sdir, &state);
            }

            if json_summary {
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
            } else {
                println!(
                    "Done: total_sources={}, succeeded={}, valid_configs={}, rejected={}, duplicates={}, expired={}, locked={}, failed={}, written_files={}",
                    res.total_sources,
                    res.succeeded_sources,
                    res.stats.valid,
                    res.stats.rejected,
                    res.stats.duplicates,
                    res.stats.expired_count,
                    res.locked_files.len(),
                    res.failed_sources.len(),
                    res.written_files.len()
                );
                println!("Protocol breakdown: {:?}", res.stats.proto_counts);
                println!("Output dir: {}", res.output_dir);
            }
        }
        Err(e) => {
            eprintln!("Batch error: {}", e);
            std::process::exit(1);
        }
    }
}
