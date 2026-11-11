use crate::builders::mihomo::build_mihomo_config;
use crate::builders::singbox::{build_singbox_config, build_singbox_outbound};
use crate::builders::xray::{build_xray_base64, build_xray_links, profile_to_xray_uri};
use crate::decoders::dark::decrypt_dark;
use crate::decoders::ehi::decrypt_ehi;
use crate::decoders::hat::decrypt_hat;
use crate::decoders::httpcustom::{decrypt_http_custom, process_hc_credentials};
use crate::decoders::netmod::decrypt_netmod;
use crate::decoders::npvs::decrypt_npvs;
use crate::decoders::npvt::decrypt_npvt;
use crate::decoders::slipnet::decrypt_slipnet;
use crate::decoders::ssccustom::decrypt_ssc;
use crate::models::{
    DecryptedSourceOutput, DecryptionError, DnsCompanionEntry, ExpiryInfo, FailedSourceReport,
    FilterStats, LockedFileReport, ProcessBatchResult, ProcessOptions, ProgressEventPayload,
    ProxyMode, ProxyProfile, SourceFileEntry, SourceKind, WrittenFileRecord,
    ALL_SUPPORTED_PROTOCOLS, MIHOMO_EXCLUSIVE_PROTOS, SUPPORTED_FILE_EXTENSIONS,
};
use crate::parsers::expiry::{check_expiration_json, check_expiration_str};
use crate::parsers::mihomo::parse_mihomo_yaml_async;
use crate::parsers::singbox::parse_singbox_json;
use crate::parsers::subscription::{
    is_dns_protocol, normalize_subscription_url, parse_subscription_text,
};
use crate::parsers::wireguard::parse_wireguard_conf;
use crate::sanitizer::{
    clean_proxy_name, filter_and_deduplicate_with_stats, unpack_v2ray_json_profile,
};
use chrono::Utc;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;
use zip::ZipArchive;

pub type ProgressCallback = Option<Arc<dyn Fn(ProgressEventPayload) + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProcessedFileRecord {
    pub path: String,
    pub size: u64,
    pub modified_unix: u64,
    pub status: String,
    pub imported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderHistory {
    pub folder_path: String,
    pub include_subfolders: bool,
    pub last_scan_utc: String,
    #[serde(default)]
    pub processed_files: BTreeMap<String, ProcessedFileRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppStateStore {
    #[serde(default)]
    pub passwords: Vec<String>,
    #[serde(default)]
    pub options: ProcessOptions,
    #[serde(default)]
    pub imported_folders: BTreeMap<String, FolderHistory>,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub last_folder_path: String,
    #[serde(default)]
    pub include_subfolders: bool,
}

fn default_theme() -> String {
    "system".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderScanResult {
    pub folder_path: String,
    pub include_subfolders: bool,
    pub new_only: bool,
    pub total_files_seen: usize,
    pub supported_files: Vec<SourceFileEntry>,
    pub unsupported_count: usize,
    pub skipped_already_imported: usize,
}

pub fn normalize_path_key(p: &Path) -> String {
    p.to_string_lossy().replace('/', "\\").to_lowercase()
}

pub fn load_app_state(state_dir: &Path) -> AppStateStore {
    let path = state_dir.join("app_state.json");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(mut parsed) = serde_json::from_str::<AppStateStore>(&raw) {
            if parsed.options.allowed_protocols.is_empty() {
                parsed.options.allowed_protocols = ALL_SUPPORTED_PROTOCOLS
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            }
            return parsed;
        }
    }
    AppStateStore::default()
}

pub fn save_app_state(state_dir: &Path, state: &AppStateStore) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|e| format!("خطا در ساخت پوشه تنظیمات: {}", e))?;
    let path = state_dir.join("app_state.json");
    let json_text =
        serde_json::to_string_pretty(state).map_err(|e| format!("خطای ذخیره تنظیمات: {}", e))?;
    fs::write(&path, json_text).map_err(|e| format!("خطا در نوشتن فایل تنظیمات: {}", e))
}

pub fn file_mtime_unix(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn normalize_extension(ext: &str) -> String {
    let lower = ext.trim_start_matches('.').to_lowercase();
    lower.split(" (").next().unwrap_or(&lower).trim().to_string()
}

pub fn is_supported_extension(ext: &str) -> bool {
    let e = normalize_extension(ext);
    SUPPORTED_FILE_EXTENSIONS.contains(&e.as_str())
}

pub fn scan_folder_files(
    folder_path: &Path,
    include_subfolders: bool,
    new_only: bool,
    history: Option<&FolderHistory>,
) -> Result<FolderScanResult, String> {
    if !folder_path.exists() || !folder_path.is_dir() {
        return Err(format!(
            "پوشه انتخاب‌شده وجود ندارد یا معتبر نیست: {}",
            folder_path.display()
        ));
    }

    let walker = if include_subfolders {
        WalkDir::new(folder_path)
    } else {
        WalkDir::new(folder_path).max_depth(1)
    };

    let mut total_files_seen = 0usize;
    let mut unsupported_count = 0usize;
    let mut skipped_already_imported = 0usize;
    let mut supported_files = Vec::new();

    for entry_res in walker.into_iter() {
        let Ok(entry) = entry_res else {
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        total_files_seen += 1;

        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if !is_supported_extension(&ext) {
            unsupported_count += 1;
            continue;
        }

        let meta = fs::metadata(path).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = meta.as_ref().map(file_mtime_unix).unwrap_or(0);
        let key = normalize_path_key(path);

        if new_only {
            if let Some(hist) = history {
                if let Some(prev) = hist.processed_files.get(&key) {
                    if prev.status == "success"
                        && prev.size == size
                        && prev.modified_unix == mtime
                    {
                        skipped_already_imported += 1;
                        continue;
                    }
                }
            }
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        supported_files.push(SourceFileEntry {
            id: key,
            name: file_name,
            path: Some(path.to_string_lossy().to_string()),
            size,
            kind: SourceKind::File,
            raw_content: None,
        });
    }

    supported_files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(FolderScanResult {
        folder_path: folder_path.to_string_lossy().to_string(),
        include_subfolders,
        new_only,
        total_files_seen,
        supported_files,
        unsupported_count,
        skipped_already_imported,
    })
}

pub fn extract_filename_password_hints(file_name: &str) -> Vec<String> {
    let mut hints = Vec::new();
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);

    let re_at = Regex::new(r"@[A-Za-z0-9_]{3,}").unwrap();
    for m in re_at.find_iter(stem) {
        let tok = m.as_str().to_string();
        let stripped = tok.trim_start_matches('@').to_string();
        hints.push(tok.clone());
        hints.push(stripped.clone());
        hints.push(tok.to_lowercase());
        hints.push(stripped.to_lowercase());
    }

    for part in stem.split(|c: char| matches!(c, ' ' | '-' | '_' | '.' | '(' | ')' | '[' | ']')) {
        let p = part.trim();
        if p.len() >= 3 {
            hints.push(p.to_string());
            if !p.starts_with('@') {
                hints.push(format!("@{}", p));
            }
            hints.push(p.to_lowercase());
        }
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for h in hints {
        if !h.is_empty() && seen.insert(h.clone()) {
            out.push(h);
        }
    }
    out
}

pub fn canonical_protocol(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "ss" | "shadowsocks" => "SHADOWSOCKS".to_string(),
        "hy2" | "hysteria2" => "HYSTERIA2".to_string(),
        "hy" | "hysteria" => "HYSTERIA".to_string(),
        "wg" | "wireguard" => "WIREGUARD".to_string(),
        "socks" | "socks5" => "SOCKS5".to_string(),
        "http" | "https" => "HTTP".to_string(),
        "naive" | "naive+https" => "NAIVE".to_string(),
        other => other.to_uppercase(),
    }
}

pub fn sanitize_filename_part(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                || (c as u32) < 0x20
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| c == ' ' || c == '.');
    if trimmed.is_empty() {
        "Source".to_string()
    } else {
        trimmed.chars().take(80).collect()
    }
}

fn attach_expiry_to_profiles(profiles: &mut [ProxyProfile], exp: &ExpiryInfo, raw_str: Option<&str>) {
    if !exp.has_expiry && raw_str.is_none() {
        return;
    }
    for p in profiles.iter_mut() {
        if p.expiry_raw.is_none() {
            p.expiry_raw = raw_str.map(|s| s.to_string());
        }
        if exp.has_expiry {
            p.is_expired = exp.is_expired;
            if p.expire_formatted.is_none() {
                p.expire_formatted = exp.formatted.clone();
            }
        }
    }
}

fn apply_password_cascade<F, T>(
    batch_passwords: &[String],
    saved_passwords: &[String],
    file_name: &str,
    mut try_decrypt: F,
) -> Result<T, DecryptionError>
where
    F: FnMut(&str) -> Result<T, DecryptionError>,
{
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let mut push_cand = |s: &str| {
        if seen.insert(s.to_string()) {
            candidates.push(s.to_string());
        }
    };

    // Priority: empty string first for non-password / app-key locked files, then batch, saved vault, filename heuristics
    push_cand("");
    for p in batch_passwords {
        push_cand(p.trim());
    }
    for p in saved_passwords {
        push_cand(p.trim());
    }
    for h in extract_filename_password_hints(file_name) {
        push_cand(&h);
    }

    let mut last_lock_err: Option<DecryptionError> = None;
    let mut last_plain_err: Option<DecryptionError> = None;

    for cand in candidates {
        match try_decrypt(&cand) {
            Ok(val) => return Ok(val),
            Err(err) => {
                if err.needs_password {
                    last_lock_err = Some(err);
                } else {
                    last_plain_err = Some(err);
                    // Non-password structural error doesn't improve by brute forcing passwords
                    if cand.is_empty() && last_lock_err.is_none() {
                        break;
                    }
                }
            }
        }
    }

    Err(last_lock_err
        .or(last_plain_err)
        .unwrap_or_else(|| DecryptionError::plain("رمزگشایی فایل ناموفق بود.")))
}

fn extract_ovpn_remote(ovpn_text: &str) -> (String, u16) {
    let re = Regex::new(r"(?im)^\s*remote\s+([^\s]+)(?:\s+(\d+))?").unwrap();
    if let Some(cap) = re.captures(ovpn_text) {
        let host = cap[1].trim().to_string();
        let port = cap
            .get(2)
            .and_then(|m| m.as_str().parse::<u16>().ok())
            .unwrap_or(1194);
        return (host, port);
    }
    ("openvpn-server".to_string(), 1194)
}

async fn decode_http_custom_full(
    raw_bytes: &[u8],
    file_name: &str,
    proxy_mode: &ProxyMode,
    custom_proxy_url: &str,
) -> Result<DecryptedSourceOutput, DecryptionError> {
    let decoded = decrypt_http_custom(raw_bytes);
    let mut profiles = Vec::new();
    let dns_companions = decoded.dns_companions.clone();

    let base_name = Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);

    let cfg_name = decoded
        .fields
        .get("name")
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| format!("HC-{}", base_name));

    if let Some(raw_ssh) = decoded.fields.get("sshField").filter(|s| !s.trim().is_empty()) {
        let cleaned_cred = process_hc_credentials(raw_ssh.trim(), true);
        // Expected formats: host:port@user:pass or user:pass@host:port or host:port
        let (hp_part, cred_part) = if let Some(at_pos) = cleaned_cred.find('@') {
            (&cleaned_cred[..at_pos], &cleaned_cred[at_pos + 1..])
        } else {
            (cleaned_cred.as_str(), "")
        };
        let (host, port) = if let Some(colon) = hp_part.rfind(':') {
            let h = hp_part[..colon].trim();
            let p = hp_part[colon + 1..].trim().parse::<u16>().unwrap_or(22);
            (h.to_string(), p)
        } else {
            (hp_part.trim().to_string(), 22)
        };
        let (user, pass) = if let Some(colon) = cred_part.find(':') {
            (
                cred_part[..colon].trim().to_string(),
                cred_part[colon + 1..].trim().to_string(),
            )
        } else {
            (cred_part.trim().to_string(), String::new())
        };
        if !host.is_empty() {
            profiles.push(ProxyProfile {
                protocol: "ssh".to_string(),
                name: cfg_name.clone(),
                server: host,
                server_port: port,
                username: user,
                password: pass,
                payload: decoded.fields.get("payload").cloned(),
                sni: decoded.fields.get("sni").cloned().unwrap_or_default(),
                ..Default::default()
            });
        }
    }

    if let Some(raw_v2) = decoded
        .fields
        .get("v2rayConfig")
        .filter(|s| !s.trim().is_empty())
    {
        if let Ok(parsed) = parse_subscription_text(raw_v2, proxy_mode, custom_proxy_url).await {
            profiles.extend(parsed.profiles);
        } else if let Ok(v) = serde_json::from_str::<Value>(raw_v2) {
            if let Some(obs) = v.get("outbounds").and_then(|o| o.as_array()) {
                for ob in obs {
                    let proto = ob.get("protocol").and_then(|x| x.as_str()).unwrap_or("");
                    if !matches!(proto, "freedom" | "blackhole" | "dns" | "") {
                        profiles.push(unpack_v2ray_json_profile(
                            &serde_json::json!({ "name": cfg_name, "v2rayJson": { "outbounds": [ob] } }),
                        ));
                    }
                }
            }
        }
    }

    if let Some(ovpn_cfg) = decoded
        .fields
        .get("ovpnConfig")
        .filter(|s| !s.trim().is_empty() && s.contains("remote "))
    {
        let (srv, port) = extract_ovpn_remote(ovpn_cfg);
        let (user, pass) = if let Some(up) = decoded.fields.get("ovpnUserAndPass") {
            let dec_up = process_hc_credentials(up, false);
            if let Some(c) = dec_up.find(':') {
                (dec_up[..c].to_string(), dec_up[c + 1..].to_string())
            } else {
                (dec_up, String::new())
            }
        } else {
            (String::new(), String::new())
        };
        profiles.push(ProxyProfile {
            protocol: "openvpn".to_string(),
            name: format!("{}-OpenVPN", cfg_name),
            server: srv,
            server_port: port,
            username: user,
            password: pass,
            ovpn_config: Some(ovpn_cfg.clone()),
            ..Default::default()
        });
    }

    let expiry_raw = decoded.fields.get("expiryTime").cloned();
    let exp = check_expiration_str(expiry_raw.as_deref());
    attach_expiry_to_profiles(&mut profiles, &exp, expiry_raw.as_deref());

    if profiles.is_empty() && dns_companions.is_empty() {
        if decoded.fields.get("blockedByPassword").map(|s| s.as_str()) == Some("true") {
            return Err(DecryptionError::plain(
                "🔒 این فایل HTTP Custom دارای قفل رمز/HWID سفارشی است و اطلاعات سرور مسدود شده‌اند.",
            ));
        }
        return Err(DecryptionError::plain(
            "اطلاعات سرور قابل استخراج در فایل HTTP Custom یافت نشد.",
        ));
    }

    Ok(DecryptedSourceOutput {
        format_type: format!("httpcustom-{}", decoded.version),
        source_name: file_name.to_string(),
        profiles,
        dns_companions,
        expiry_info: if exp.has_expiry { Some(exp) } else { None },
        warning_message: None,
    })
}

pub fn decode_bytes_sync_or_async<'a>(
    raw_bytes: &'a [u8],
    file_name: &'a str,
    batch_passwords: &'a [String],
    saved_passwords: &'a [String],
    proxy_mode: &'a ProxyMode,
    custom_proxy_url: &'a str,
    depth: u8,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<DecryptedSourceOutput, DecryptionError>> + Send + 'a>,
> {
    Box::pin(async move {
        let raw_ext = Path::new(file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let ext = normalize_extension(raw_ext);
        let text = String::from_utf8_lossy(raw_bytes).into_owned();
        let trimmed = text.trim_start_matches('\u{FEFF}').trim();

        // 1. ZIP Archive recursion
        if ext == "zip" || (raw_bytes.len() >= 4 && &raw_bytes[0..4] == b"PK\x03\x04") {
            if depth >= 2 {
                return Err(DecryptionError::plain(
                    "عمق فایل فشرده ZIP بیش از حد مجاز است.",
                ));
            }
            let cursor = Cursor::new(raw_bytes);
            let mut archive = ZipArchive::new(cursor).map_err(|e| {
                DecryptionError::plain(format!("خطا در باز کردن فایل ZIP: {}", e))
            })?;
            let mut combined_profiles = Vec::new();
            let mut combined_dns = Vec::new();
            let mut warnings = Vec::new();

            for i in 0..archive.len() {
                let Ok(mut entry) = archive.by_index(i) else {
                    continue;
                };
                if entry.is_dir() {
                    continue;
                }
                let inner_name = entry.name().to_string();
                let mut buf = Vec::new();
                if entry.read_to_end(&mut buf).is_err() || buf.is_empty() {
                    continue;
                }
                match decode_bytes_sync_or_async(
                    &buf,
                    &inner_name,
                    batch_passwords,
                    saved_passwords,
                    proxy_mode,
                    custom_proxy_url,
                    depth + 1,
                )
                .await
                {
                    Ok(sub) => {
                        combined_profiles.extend(sub.profiles);
                        combined_dns.extend(sub.dns_companions);
                    }
                    Err(e) => {
                        warnings.push(format!("{}: {}", inner_name, e.message));
                    }
                }
            }
            if combined_profiles.is_empty() && combined_dns.is_empty() {
                return Err(DecryptionError::plain(if warnings.is_empty() {
                    "فایل ZIP حاوی کانفیگ معتبری نبود.".to_string()
                } else {
                    warnings.join(" | ")
                }));
            }
            return Ok(DecryptedSourceOutput {
                format_type: "zip".to_string(),
                source_name: file_name.to_string(),
                profiles: combined_profiles,
                dns_companions: combined_dns,
                expiry_info: None,
                warning_message: if warnings.is_empty() {
                    None
                } else {
                    Some(warnings.join("\n"))
                },
            });
        }

        // 2. NPVS binary magic or .npvs/.npv/.npv4
        let is_npvs_magic = raw_bytes.len() >= 4 && &raw_bytes[0..4] == b"NPVS";
        if is_npvs_magic || matches!(ext.as_str(), "npvs" | "npv" | "npv4") {
            let decoded =
                apply_password_cascade(batch_passwords, saved_passwords, file_name, |pwd| {
                    decrypt_npvs(raw_bytes, pwd)
                })?;
            let exp = check_expiration_json(&decoded.policy);
            let exp_raw = decoded
                .policy
                .get("expiresAt")
                .map(|v| v.to_string().trim_matches('"').to_string());
            let mut profiles = Vec::new();
            for val in &decoded.profiles {
                if let Some(s) = val.as_str() {
                    if let Some(p) = crate::parsers::subscription::parse_uri_config(s) {
                        profiles.push(p);
                    }
                } else if val.is_object() {
                    let mut p = unpack_v2ray_json_profile(val);
                    if p.server.is_empty() {
                        if let Some(uri) = val
                            .get("uri")
                            .or_else(|| val.get("link"))
                            .and_then(|v| v.as_str())
                        {
                            if let Some(parsed_u) = crate::parsers::subscription::parse_uri_config(uri)
                            {
                                p = parsed_u;
                            }
                        }
                    }
                    profiles.push(p);
                }
            }
            attach_expiry_to_profiles(&mut profiles, &exp, exp_raw.as_deref());
            return Ok(DecryptedSourceOutput {
                format_type: format!("npvs-v{} ({})", decoded.version, decoded.used_method),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: Vec::new(),
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 3. NPVT / INPV
        if ext == "npvt"
            || ext == "inpv"
            || trimmed.starts_with("NPVT1")
            || trimmed.starts_with("NPVTSUB1")
            || trimmed.starts_with("1]")
        {
            let decoded = decrypt_npvt(trimmed)?;
            let mut profiles: Vec<ProxyProfile> = Vec::new();
            for item in &decoded.profiles {
                if let Some(s) = item.as_str() {
                    if let Some(p) = crate::parsers::subscription::parse_uri_config(s) {
                        profiles.push(p);
                    }
                } else {
                    profiles.push(unpack_v2ray_json_profile(item));
                }
            }
            let exp = decoded
                .settings
                .as_ref()
                .map(check_expiration_json)
                .unwrap_or_default();
            attach_expiry_to_profiles(&mut profiles, &exp, None);
            return Ok(DecryptedSourceOutput {
                format_type: decoded.kind,
                source_name: file_name.to_string(),
                profiles,
                dns_companions: Vec::new(),
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 4. DarkTunnel (.dark / darktunnel://)
        if ext == "dark" || trimmed.starts_with("darktunnel://") {
            let decoded = decrypt_dark(trimmed)?;
            let exp = check_expiration_json(&decoded.parsed);
            let mut profiles = decoded.profiles;
            attach_expiry_to_profiles(&mut profiles, &exp, None);
            return Ok(DecryptedSourceOutput {
                format_type: "darktunnel".to_string(),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: decoded.dns_companions,
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 5. NetMod (.nm / nm-)
        if ext == "nm" || trimmed.to_lowercase().starts_with("nm-") {
            let decoded = decrypt_netmod(trimmed)?;
            let exp = check_expiration_json(&decoded.parsed);
            let mut profiles = decoded.profiles;
            attach_expiry_to_profiles(&mut profiles, &exp, None);
            return Ok(DecryptedSourceOutput {
                format_type: "netmod".to_string(),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: decoded.dns_companions,
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 6. HA Tunnel Plus (.hat)
        if ext == "hat" {
            let decoded = decrypt_hat(trimmed)?;
            let exp = check_expiration_json(&decoded.parsed);
            let mut profiles = decoded.profiles;
            attach_expiry_to_profiles(&mut profiles, &exp, None);
            return Ok(DecryptedSourceOutput {
                format_type: "hatunnel".to_string(),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: Vec::new(),
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 7. SlipNet (.slip)
        if ext == "slip" {
            let decoded = decrypt_slipnet(trimmed);
            let exp_raw = decoded.fields.get("Expiration Date").cloned();
            let exp = check_expiration_str(exp_raw.as_deref());
            let mut profiles = decoded.profiles;
            attach_expiry_to_profiles(&mut profiles, &exp, exp_raw.as_deref());
            return Ok(DecryptedSourceOutput {
                format_type: format!("slipnet-{}", decoded.proto),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: decoded.dns_companions,
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 8. SSC Custom (.ssc / ssc://)
        if ext == "ssc" || trimmed.starts_with("ssc://") {
            let decoded = decrypt_ssc(trimmed, file_name)?;
            let exp = check_expiration_str(decoded.expiry_raw.as_deref());
            let mut profiles = decoded.profiles;
            attach_expiry_to_profiles(&mut profiles, &exp, decoded.expiry_raw.as_deref());
            return Ok(DecryptedSourceOutput {
                format_type: "ssccustom".to_string(),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: Vec::new(),
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 9. HTTP Custom (.hc)
        if ext == "hc" {
            return decode_http_custom_full(raw_bytes, file_name, proxy_mode, custom_proxy_url)
                .await;
        }

        // 10. HTTP Injector (.ehi)
        if ext == "ehi" {
            let decoded = decrypt_ehi(raw_bytes)?;
            let mut profiles = Vec::new();
            for raw_ob in &decoded.raw_profiles_json {
                profiles.push(unpack_v2ray_json_profile(
                    &serde_json::json!({ "name": file_name, "v2rayJson": { "outbounds": [raw_ob] } }),
                ));
            }
            profiles.extend(decoded.profiles);
            let exp = check_expiration_str(decoded.expiry_raw.as_deref());
            attach_expiry_to_profiles(&mut profiles, &exp, decoded.expiry_raw.as_deref());
            return Ok(DecryptedSourceOutput {
                format_type: format!("ehi-{}", decoded.mode),
                source_name: file_name.to_string(),
                profiles,
                dns_companions: Vec::new(),
                expiry_info: if exp.has_expiry { Some(exp) } else { None },
                warning_message: None,
            });
        }

        // 11. BPF (.bpf gzipped payload)
        if ext == "bpf" {
            let gz_offset = (0..raw_bytes.len().saturating_sub(2).min(12))
                .find(|&i| raw_bytes[i] == 0x1f && raw_bytes[i + 1] == 0x8b);
            if let Some(off) = gz_offset {
                let mut decoder = GzDecoder::new(&raw_bytes[off..]);
                let mut decompressed = String::new();
                if decoder.read_to_string(&mut decompressed).is_ok()
                    && !decompressed.trim().is_empty()
                {
                    return decode_bytes_sync_or_async(
                        decompressed.as_bytes(),
                        &format!("{}.json", file_name),
                        batch_passwords,
                        saved_passwords,
                        proxy_mode,
                        custom_proxy_url,
                        depth + 1,
                    )
                    .await;
                }
            }
            return Err(DecryptionError::plain("رمزگشایی فایل BPF ناموفق بود."));
        }

        // 12. OpenVPN (.ovpn)
        if ext == "ovpn" || (trimmed.contains("remote ") && trimmed.contains("<ca>")) {
            let (srv, port) = extract_ovpn_remote(trimmed);
            let name = Path::new(file_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("OpenVPN")
                .to_string();
            return Ok(DecryptedSourceOutput {
                format_type: "openvpn".to_string(),
                source_name: file_name.to_string(),
                profiles: vec![ProxyProfile {
                    protocol: "openvpn".to_string(),
                    name,
                    server: srv,
                    server_port: port,
                    ovpn_config: Some(trimmed.to_string()),
                    ..Default::default()
                }],
                dns_companions: Vec::new(),
                expiry_info: None,
                warning_message: None,
            });
        }

        // 13. WireGuard (.conf)
        if ext == "conf" || (trimmed.contains("[Interface]") && trimmed.contains("[Peer]")) {
            if let Ok(p) = parse_wireguard_conf(trimmed, file_name) {
                return Ok(DecryptedSourceOutput {
                    format_type: "wireguard".to_string(),
                    source_name: file_name.to_string(),
                    profiles: vec![p],
                    dns_companions: Vec::new(),
                    expiry_info: None,
                    warning_message: None,
                });
            }
        }

        // 14. YAML / Mihomo (.yaml, .yml)
        if matches!(ext.as_str(), "yaml" | "yml") {
            if let Ok(profiles) =
                parse_mihomo_yaml_async(trimmed, proxy_mode, custom_proxy_url).await
            {
                if !profiles.is_empty() {
                    return Ok(DecryptedSourceOutput {
                        format_type: "mihomo".to_string(),
                        source_name: file_name.to_string(),
                        profiles,
                        dns_companions: Vec::new(),
                        expiry_info: None,
                        warning_message: None,
                    });
                }
            }
        }

        // 15. JSON (.json) - Sing-box / Xray / Clash JSON / Generic V2Ray JSON
        if ext == "json" || trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(sb) = parse_singbox_json(trimmed, file_name) {
                if !sb.is_empty() {
                    return Ok(DecryptedSourceOutput {
                        format_type: "singbox".to_string(),
                        source_name: file_name.to_string(),
                        profiles: sb,
                        dns_companions: Vec::new(),
                        expiry_info: None,
                        warning_message: None,
                    });
                }
            }
            if let Ok(sub) = parse_subscription_text(trimmed, proxy_mode, custom_proxy_url).await {
                if !sub.profiles.is_empty() {
                    return Ok(DecryptedSourceOutput {
                        format_type: sub.format_type,
                        source_name: file_name.to_string(),
                        profiles: sub.profiles,
                        dns_companions: Vec::new(),
                        expiry_info: None,
                        warning_message: None,
                    });
                }
            }
        }

        // 16. Subscription / Generic Text / Messy Links fallback
        let parsed = parse_subscription_text(trimmed, proxy_mode, custom_proxy_url).await?;
        if parsed.profiles.is_empty() {
            return Err(DecryptionError::plain(
                "هیچ کانفیگ معتبری از این فایل استخراج نشد.",
            ));
        }

        Ok(DecryptedSourceOutput {
            format_type: parsed.format_type,
            source_name: file_name.to_string(),
            profiles: parsed.profiles,
            dns_companions: Vec::new(),
            expiry_info: None,
            warning_message: None,
        })
    })
}

fn format_ssh_companion(ssh_profiles: &[ProxyProfile]) -> String {
    if ssh_profiles.is_empty() {
        return String::new();
    }
    let mut blocks = Vec::new();
    let mut uri_lines = Vec::new();
    for (idx, p) in ssh_profiles.iter().enumerate() {
        let mut lines = vec![
            format!("=== کانفیگ SSH #{} ===", idx + 1),
            format!("نام: {}", clean_proxy_name(&p.name, "SSH")),
            format!(
                "سرور: {}:{}",
                p.server,
                if p.server_port == 0 { 22 } else { p.server_port }
            ),
            format!("نام کاربری: {}", p.username),
            format!("رمز عبور: {}", p.password),
        ];
        if !p.sni.is_empty() {
            lines.push(format!("SNI / Host: {}", p.sni));
        }
        if let Some(ref payload) = p.payload {
            if !payload.trim().is_empty() {
                lines.push(format!("Payload:\n{}", payload.trim()));
            }
        }
        if let Some(uri) = profile_to_xray_uri(p) {
            lines.push(format!("لینک: {}", uri));
            uri_lines.push(uri);
        }
        blocks.push(lines.join("\n"));
    }
    if !uri_lines.is_empty() {
        blocks.push(format!("--- لیست لینک‌ها ---\n{}", uri_lines.join("\n")));
    }
    blocks.join("\n\n")
}

fn format_dns_companion(dns_entries: &[DnsCompanionEntry], dns_profiles: &[ProxyProfile]) -> String {
    let mut blocks = Vec::new();
    for e in dns_entries {
        blocks.push(format!("[{}] {}\n{}", e.kind, e.title, e.summary));
    }
    for p in dns_profiles {
        let mut block = format!(
            "[{}] {}\nسرور/دامنه: {}:{}",
            p.protocol.to_uppercase(),
            p.name,
            p.server,
            p.server_port
        );
        if let Some(ref raw) = p.raw_uri {
            block.push_str(&format!("\nلینک خام: {}", raw));
        }
        blocks.push(block);
    }
    blocks.join("\n\n")
}

fn write_text_file(
    target_dir: &Path,
    file_name: &str,
    rel_prefix: &str,
    category: &str,
    format: &str,
    content: &str,
    written: &mut Vec<WrittenFileRecord>,
) -> Result<(), String> {
    if content.trim().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(target_dir)
        .map_err(|e| format!("خطا در ساخت پوشه خروجی ({}): {}", target_dir.display(), e))?;
    let full_path = target_dir.join(file_name);
    fs::write(&full_path, content.as_bytes())
        .map_err(|e| format!("خطا در نوشتن فایل خروجی ({}): {}", full_path.display(), e))?;
    let rel = if rel_prefix.is_empty() {
        file_name.to_string()
    } else {
        format!("{}/{}", rel_prefix, file_name)
    };
    written.push(WrittenFileRecord {
        path: full_path.to_string_lossy().to_string(),
        rel_path: rel,
        category: category.to_string(),
        format: format.to_string(),
        size_bytes: content.len() as u64,
    });
    Ok(())
}

struct GeneratedPreviews {
    xray: String,
    xray_base64: String,
    singbox: String,
    mihomo: String,
    companions: BTreeMap<String, String>,
}

fn generate_bucket_outputs(
    base_dir: &Path,
    rel_prefix: &str,
    category: &str,
    profiles: &[ProxyProfile],
    dns_companions: &[DnsCompanionEntry],
    options: &ProcessOptions,
    write_to_disk: bool,
    written: &mut Vec<WrittenFileRecord>,
) -> Result<GeneratedPreviews, String> {
    let mut standard_profiles = Vec::new();
    let mut ssh_profiles = Vec::new();
    let mut ovpn_profiles = Vec::new();
    let mut dns_profiles = Vec::new();
    let mut mihomo_exclusive = Vec::new();

    for p in profiles {
        let lp = p.protocol.to_lowercase();
        if p.is_dns_tunnel || is_dns_protocol(&lp) {
            dns_profiles.push(p.clone());
        } else if lp == "openvpn" {
            ovpn_profiles.push(p.clone());
        } else {
            if lp == "ssh" {
                ssh_profiles.push(p.clone());
            }
            if MIHOMO_EXCLUSIVE_PROTOS.contains(&lp.as_str()) {
                mihomo_exclusive.push(p.clone());
            }
            standard_profiles.push(p.clone());
        }
    }

    let mut previews = GeneratedPreviews {
        xray: String::new(),
        xray_base64: String::new(),
        singbox: String::new(),
        mihomo: String::new(),
        companions: BTreeMap::new(),
    };

    // Build all-protocols previews regardless of disk toggles so UI tabs can preview active configs
    let xray_txt = build_xray_links(
        &standard_profiles,
        options.filter_duplicates,
        options.filter_broken,
        true,
    );
    let xray_b64 = build_xray_base64(&xray_txt);
    let has_sb = standard_profiles
        .iter()
        .enumerate()
        .any(|(i, p)| build_singbox_outbound(p, i).is_some());
    let sb_json = if has_sb {
        build_singbox_config(
            &standard_profiles,
            options.filter_duplicates,
            options.filter_broken,
            true,
        )
    } else {
        String::new()
    };
    let mihomo_yaml = if !standard_profiles.is_empty() {
        build_mihomo_config(
            &standard_profiles,
            options.filter_duplicates,
            options.filter_broken,
            true,
        )
    } else {
        String::new()
    };

    previews.xray = xray_txt.clone();
    previews.xray_base64 = xray_b64.clone();
    previews.singbox = sb_json.clone();
    previews.mihomo = mihomo_yaml.clone();

    let ovpn_str: String = ovpn_profiles
        .iter()
        .filter_map(|p| p.ovpn_config.as_ref().map(|s| s.trim().to_string()))
        .collect::<Vec<_>>()
        .join("\n\n# -----------------------------\n\n");
    let ssh_str = format_ssh_companion(&ssh_profiles);
    let dns_str = format_dns_companion(dns_companions, &dns_profiles);
    let mihomo_excl_str = if !mihomo_exclusive.is_empty() {
        build_mihomo_config(&mihomo_exclusive, false, false, true)
    } else {
        String::new()
    };

    if !ovpn_str.is_empty() {
        previews.companions.insert("OpenVPN".into(), ovpn_str.clone());
    }
    if !ssh_str.is_empty() {
        previews.companions.insert("SSH".into(), ssh_str.clone());
    }
    if !dns_str.is_empty() {
        previews.companions.insert("DNS".into(), dns_str.clone());
    }
    if !mihomo_excl_str.is_empty() {
        previews
            .companions
            .insert("Mihomo Exclusive".into(), mihomo_excl_str.clone());
    }

    if !write_to_disk {
        return Ok(previews);
    }

    // 1. All_Protocols level
    if options.protocol_split.all_protocols {
        if options.output_formats.xray && !xray_txt.is_empty() {
            write_text_file(
                base_dir,
                "all_xray.txt",
                rel_prefix,
                category,
                "xray",
                &xray_txt,
                written,
            )?;
        }
        if options.output_formats.xray_base64 && !xray_b64.is_empty() {
            write_text_file(
                base_dir,
                "all_xray_base64.txt",
                rel_prefix,
                category,
                "xray_base64",
                &xray_b64,
                written,
            )?;
        }
        if options.output_formats.singbox && !sb_json.is_empty() {
            write_text_file(
                base_dir,
                "all_singbox.json",
                rel_prefix,
                category,
                "singbox",
                &sb_json,
                written,
            )?;
        }
        if options.output_formats.mihomo && !mihomo_yaml.is_empty() {
            write_text_file(
                base_dir,
                "all_mihomo.yaml",
                rel_prefix,
                category,
                "mihomo",
                &mihomo_yaml,
                written,
            )?;
        }
    }

    // 2. By_Protocol level (<PROTO>_xray.txt, <PROTO>_singbox.json, <PROTO>_mihomo.yaml)
    if options.protocol_split.by_protocol {
        let mut by_proto: BTreeMap<String, Vec<ProxyProfile>> = BTreeMap::new();
        for p in &standard_profiles {
            let key = canonical_protocol(&p.protocol);
            by_proto.entry(key).or_default().push(p.clone());
        }
        let proto_dir = base_dir.join("By_Protocol");
        let proto_rel = if rel_prefix.is_empty() {
            "By_Protocol".to_string()
        } else {
            format!("{}/By_Protocol", rel_prefix)
        };
        for (proto_name, plist) in by_proto {
            let p_xray = build_xray_links(&plist, false, false, true);
            if options.output_formats.xray && !p_xray.is_empty() {
                write_text_file(
                    &proto_dir,
                    &format!("{}_xray.txt", proto_name),
                    &proto_rel,
                    category,
                    "xray",
                    &p_xray,
                    written,
                )?;
            }
            if options.output_formats.xray_base64 && !p_xray.is_empty() {
                let p_b64 = build_xray_base64(&p_xray);
                write_text_file(
                    &proto_dir,
                    &format!("{}_xray_base64.txt", proto_name),
                    &proto_rel,
                    category,
                    "xray_base64",
                    &p_b64,
                    written,
                )?;
            }
            if options.output_formats.singbox
                && plist
                    .iter()
                    .enumerate()
                    .any(|(i, x)| build_singbox_outbound(x, i).is_some())
            {
                let p_sb = build_singbox_config(&plist, false, false, true);
                write_text_file(
                    &proto_dir,
                    &format!("{}_singbox.json", proto_name),
                    &proto_rel,
                    category,
                    "singbox",
                    &p_sb,
                    written,
                )?;
            }
            if options.output_formats.mihomo {
                let p_mh = build_mihomo_config(&plist, false, false, true);
                if p_mh.contains("- name:") && !p_mh.contains("  - name: \"DIRECT\"") {
                    write_text_file(
                        &proto_dir,
                        &format!("{}_mihomo.yaml", proto_name),
                        &proto_rel,
                        category,
                        "mihomo",
                        &p_mh,
                        written,
                    )?;
                }
            }
        }
    }

    // 3. Companions
    if options.output_formats.companions {
        let comp_dir = base_dir.join("Companions");
        let comp_rel = if rel_prefix.is_empty() {
            "Companions".to_string()
        } else {
            format!("{}/Companions", rel_prefix)
        };
        if !ovpn_str.is_empty() {
            write_text_file(
                &comp_dir,
                "_OpenVPN.ovpn",
                &comp_rel,
                category,
                "companion",
                &ovpn_str,
                written,
            )?;
        }
        if !ssh_str.is_empty() {
            write_text_file(
                &comp_dir,
                "_SSH.txt",
                &comp_rel,
                category,
                "companion",
                &ssh_str,
                written,
            )?;
        }
        if !dns_str.is_empty() {
            write_text_file(
                &comp_dir,
                "_DNS.txt",
                &comp_rel,
                category,
                "companion",
                &dns_str,
                written,
            )?;
        }
        if !mihomo_excl_str.is_empty() {
            write_text_file(
                &comp_dir,
                "_Mihomo_clash.yaml",
                &comp_rel,
                category,
                "companion",
                &mihomo_excl_str,
                written,
            )?;
        }
    }

    Ok(previews)
}

fn filter_by_options(
    raw_profiles: Vec<ProxyProfile>,
    options: &ProcessOptions,
) -> (Vec<ProxyProfile>, FilterStats) {
    let mut expired_count = 0usize;
    let mut non_expired = Vec::new();
    for p in raw_profiles {
        if options.ignore_expired && p.is_expired {
            expired_count += 1;
            continue;
        }
        non_expired.push(p);
    }

    let allowed_set: HashSet<String> = options
        .allowed_protocols
        .iter()
        .map(|s| canonical_protocol(s))
        .collect();
    let enforce_proto_filter = !allowed_set.is_empty()
        && allowed_set.len() < ALL_SUPPORTED_PROTOCOLS.len();

    let (mut valid, mut stats) = filter_and_deduplicate_with_stats(
        &non_expired,
        options.filter_duplicates,
        options.filter_broken,
    );
    stats.expired_count = expired_count;

    if enforce_proto_filter {
        valid.retain(|p| {
            let cp = canonical_protocol(&p.protocol);
            allowed_set.contains(&cp) || p.is_dns_tunnel
        });
        stats.valid = valid.len();
        stats.proto_counts.clear();
        for p in &valid {
            *stats
                .proto_counts
                .entry(canonical_protocol(&p.protocol))
                .or_insert(0) += 1;
        }
    }

    if options.limit_max_configs && valid.len() > options.max_configs_count {
        valid.truncate(options.max_configs_count);
        stats.valid = valid.len();
        stats.proto_counts.clear();
        for p in &valid {
            *stats
                .proto_counts
                .entry(canonical_protocol(&p.protocol))
                .or_insert(0) += 1;
        }
    }

    (valid, stats)
}

pub async fn process_batch(
    sources: &[SourceFileEntry],
    subscription_urls_text: &str,
    messy_text: &str,
    batch_passwords: &[String],
    saved_passwords: &[String],
    options: &ProcessOptions,
    progress_cb: ProgressCallback,
) -> Result<ProcessBatchResult, String> {
    let mut queue: Vec<SourceFileEntry> = sources.to_vec();

    for (idx, line) in subscription_urls_text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let norm_url = normalize_subscription_url(trimmed);
        queue.push(SourceFileEntry {
            id: format!("sub-{}", idx + 1),
            name: format!("Sub_{}", idx + 1),
            path: None,
            size: trimmed.len() as u64,
            kind: SourceKind::SubscriptionUrl,
            raw_content: Some(norm_url),
        });
    }

    if !messy_text.trim().is_empty() {
        queue.push(SourceFileEntry {
            id: "messy-input".to_string(),
            name: "MessyText_Input".to_string(),
            path: None,
            size: messy_text.len() as u64,
            kind: SourceKind::MessyText,
            raw_content: Some(messy_text.to_string()),
        });
    }

    if queue.is_empty() {
        return Err("هیچ فایل، لینک اشتراک یا متن ورودی برای پردازش انتخاب نشده است.".to_string());
    }

    let total_sources = queue.len();
    let mut succeeded_sources = 0usize;
    let mut moved_to_trash_count = 0usize;
    let mut locked_files = Vec::new();
    let mut failed_sources = Vec::new();

    struct PerSourceData {
        source_name: String,
        profiles: Vec<ProxyProfile>,
        dns_companions: Vec<DnsCompanionEntry>,
    }

    let mut per_source_results: Vec<PerSourceData> = Vec::new();
    let mut all_raw_profiles: Vec<ProxyProfile> = Vec::new();
    let mut all_dns_companions: Vec<DnsCompanionEntry> = Vec::new();

    for (idx, item) in queue.iter().enumerate() {
        if let Some(ref cb) = progress_cb {
            let pct = (((idx + 1) * 80) / total_sources.max(1)).min(85) as u8;
            cb(ProgressEventPayload {
                current: idx + 1,
                total: total_sources,
                percent: pct,
                current_item: item.name.clone(),
                stage: "decrypting".to_string(),
            });
        }

        let decode_res: Result<DecryptedSourceOutput, DecryptionError> = match item.kind {
            SourceKind::File => {
                let raw_bytes = if let Some(ref raw_text) = item.raw_content {
                    Ok(raw_text.as_bytes().to_vec())
                } else if let Some(ref path_str) = item.path {
                    fs::read(path_str).map_err(|e| {
                        DecryptionError::plain(format!("خطا در خواندن فایل از دیسک: {}", e))
                    })
                } else {
                    Err(DecryptionError::plain("مسیر فایل نامعتبر است."))
                };
                match raw_bytes {
                    Ok(bytes) => {
                        decode_bytes_sync_or_async(
                            &bytes,
                            &item.name,
                            batch_passwords,
                            saved_passwords,
                            &options.proxy_mode,
                            &options.custom_proxy_url,
                            0,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            SourceKind::SubscriptionUrl | SourceKind::MessyText => {
                let content = item.raw_content.as_deref().unwrap_or("");
                match parse_subscription_text(
                    content,
                    &options.proxy_mode,
                    &options.custom_proxy_url,
                )
                .await
                {
                    Ok(parsed) => {
                        if parsed.profiles.is_empty() {
                            Err(DecryptionError::plain(
                                "هیچ کانفیگ معتبری در این ورودی یافت نشد.",
                            ))
                        } else {
                            Ok(DecryptedSourceOutput {
                                format_type: parsed.format_type,
                                source_name: item.name.clone(),
                                profiles: parsed.profiles,
                                dns_companions: Vec::new(),
                                expiry_info: None,
                                warning_message: None,
                            })
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        };

        match decode_res {
            Ok(out) => {
                succeeded_sources += 1;
                all_raw_profiles.extend(out.profiles.clone());
                all_dns_companions.extend(out.dns_companions.clone());
                per_source_results.push(PerSourceData {
                    source_name: item.name.clone(),
                    profiles: out.profiles,
                    dns_companions: out.dns_companions,
                });
                if options.move_decrypted_to_trash && item.kind == SourceKind::File {
                    if let Some(ref path_str) = item.path {
                        if trash::delete(path_str).is_ok() {
                            moved_to_trash_count += 1;
                        }
                    }
                }
            }
            Err(err) => {
                if err.needs_password {
                    locked_files.push(LockedFileReport {
                        source_id: item.id.clone(),
                        file_name: item.name.clone(),
                        file_path: item.path.clone(),
                        display_message: err.display_message,
                        error: err.message,
                    });
                } else {
                    failed_sources.push(FailedSourceReport {
                        source_id: item.id.clone(),
                        file_name: item.name.clone(),
                        file_path: item.path.clone(),
                        error: err.message,
                    });
                }
            }
        }
    }

    if let Some(ref cb) = progress_cb {
        cb(ProgressEventPayload {
            current: total_sources,
            total: total_sources,
            percent: 90,
            current_item: "تولید خروجی‌ها...".to_string(),
            stage: "building".to_string(),
        });
    }

    let (mixed_valid, mix_stats) = filter_by_options(all_raw_profiles, options);

    let out_dir_path = if options.output_dir.trim().is_empty() {
        let ts = Utc::now().format("%Y%m%d_%H%M%S");
        PathBuf::from("Outputs").join(format!("Run_{}", ts))
    } else {
        PathBuf::from(options.output_dir.trim())
    };

    let should_write_any = options.output_scope.mix_all || options.output_scope.per_source;
    let mut written_files = Vec::new();

    // Generate Mix_All (always compute previews, write only if mix_all enabled)
    let previews = generate_bucket_outputs(
        &out_dir_path.join("Mix_All"),
        "Mix_All",
        "mix_all",
        &mixed_valid,
        &all_dns_companions,
        options,
        should_write_any && options.output_scope.mix_all,
        &mut written_files,
    )?;

    // Generate Per_Source
    if options.output_scope.per_source {
        let mut used_folder_names = HashSet::new();
        for src in &per_source_results {
            let (src_valid, _) = filter_by_options(src.profiles.clone(), options);
            if src_valid.is_empty() && src.dns_companions.is_empty() {
                continue;
            }
            let stem = Path::new(&src.source_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&src.source_name);
            let base = sanitize_filename_part(stem);
            let mut folder_name = base.clone();
            let mut cnt = 2usize;
            while !used_folder_names.insert(folder_name.to_lowercase()) {
                folder_name = format!("{}_{}", base, cnt);
                cnt += 1;
            }
            let rel = format!("Per_Source/{}", folder_name);
            generate_bucket_outputs(
                &out_dir_path.join("Per_Source").join(&folder_name),
                &rel,
                "per_source",
                &src_valid,
                &src.dns_companions,
                options,
                true,
                &mut written_files,
            )?;
        }
    }

    if let Some(ref cb) = progress_cb {
        cb(ProgressEventPayload {
            current: total_sources,
            total: total_sources,
            percent: 100,
            current_item: "تکمیل شد".to_string(),
            stage: "done".to_string(),
        });
    }

    Ok(ProcessBatchResult {
        stats: mix_stats,
        total_sources,
        succeeded_sources,
        moved_to_trash_count,
        locked_files,
        failed_sources,
        written_files,
        preview_xray: previews.xray,
        preview_xray_base64: previews.xray_base64,
        preview_singbox: previews.singbox,
        preview_mihomo: previews.mihomo,
        preview_companions: previews.companions,
        output_dir: out_dir_path.to_string_lossy().to_string(),
    })
}

pub fn record_folder_history(
    state: &mut AppStateStore,
    folder_path: Option<&str>,
    include_subfolders: bool,
    sources: &[SourceFileEntry],
    res: &ProcessBatchResult,
) {
    let Some(folder_str) = folder_path.filter(|s| !s.trim().is_empty()) else {
        return;
    };
    let folder_key = normalize_path_key(Path::new(folder_str));
    let locked_ids: HashSet<String> = res
        .locked_files
        .iter()
        .map(|l| l.source_id.clone())
        .collect();
    let failed_ids: HashSet<String> = res
        .failed_sources
        .iter()
        .map(|f| f.source_id.clone())
        .collect();

    let hist = state
        .imported_folders
        .entry(folder_key)
        .or_insert_with(|| FolderHistory {
            folder_path: folder_str.to_string(),
            include_subfolders,
            last_scan_utc: String::new(),
            processed_files: Default::default(),
        });
    hist.include_subfolders = include_subfolders;
    let now_str = Utc::now().to_rfc3339();
    hist.last_scan_utc = now_str.clone();

    for s in sources {
        if s.kind != SourceKind::File {
            continue;
        }
        let Some(ref path_str) = s.path else {
            continue;
        };
        let status = if locked_ids.contains(&s.id) {
            "locked"
        } else if failed_ids.contains(&s.id) {
            "failed"
        } else {
            "success"
        };
        let mtime = fs::metadata(path_str)
            .map(|m| file_mtime_unix(&m))
            .unwrap_or(0);
        hist.processed_files.insert(
            s.id.clone(),
            ProcessedFileRecord {
                path: path_str.clone(),
                size: s.size,
                modified_unix: mtime,
                status: status.to_string(),
                imported_at: now_str.clone(),
            },
        );
    }
}
