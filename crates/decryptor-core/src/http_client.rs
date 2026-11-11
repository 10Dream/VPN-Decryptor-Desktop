use crate::models::ProxyMode;
use std::collections::HashMap;
use std::env;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const KNOWN_LOCAL_HTTP_PORTS: &[u16] = &[7890, 7897, 11223, 10809, 12334, 2334, 2081];
const PROXY_CACHE_TTL: Duration = Duration::from_secs(20);
const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

static PROXY_CACHE: OnceLock<Mutex<Option<(Instant, Option<String>)>>> = OnceLock::new();
static SYS_PROXY_CACHE: OnceLock<Mutex<Option<(Instant, Option<String>)>>> = OnceLock::new();
static CLIENT_POOL: OnceLock<Mutex<HashMap<Option<String>, reqwest::Client>>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn read_windows_system_proxy_uncached() -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let enabled_out = Command::new("reg")
        .args(["query", REG_KEY, "/v", "ProxyEnable"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let enabled_str = String::from_utf8_lossy(&enabled_out.stdout);
    let is_enabled = enabled_str.contains("0x1") || enabled_str.contains("1");
    if !is_enabled {
        return None;
    }

    let srv_out = Command::new("reg")
        .args(["query", REG_KEY, "/v", "ProxyServer"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let srv_str = String::from_utf8_lossy(&srv_out.stdout);
    for line in srv_str.lines() {
        if line.contains("ProxyServer") {
            if let Some(val) = line.split_whitespace().last() {
                let cleaned = val.trim();
                if cleaned.is_empty() {
                    continue;
                }
                if cleaned.starts_with("http://")
                    || cleaned.starts_with("https://")
                    || cleaned.starts_with("socks")
                {
                    return Some(cleaned.to_string());
                }
                if cleaned.contains(':') && !cleaned.contains('=') {
                    return Some(format!("http://{}", cleaned));
                }
                for seg in cleaned.split(';') {
                    if let Some((_, hp)) = seg.split_once('=') {
                        if !hp.trim().is_empty() {
                            return Some(format!("http://{}", hp.trim()));
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn read_windows_system_proxy_uncached() -> Option<String> {
    None
}

fn read_windows_system_proxy_cached() -> Option<String> {
    let lock = SYS_PROXY_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < PROXY_CACHE_TTL {
                return cached.clone();
            }
        }
    }
    let fresh = read_windows_system_proxy_uncached();
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((Instant::now(), fresh.clone()));
    }
    fresh
}

pub fn detect_active_local_proxy_fresh() -> Option<String> {
    for key in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                let lock = PROXY_CACHE.get_or_init(|| Mutex::new(None));
                if let Ok(mut guard) = lock.lock() {
                    *guard = Some((Instant::now(), Some(trimmed.clone())));
                }
                return Some(trimmed);
            }
        }
    }
    let result = if let Some(sys_p) = read_windows_system_proxy_cached() {
        Some(sys_p)
    } else {
        let mut found = None;
        for &port in KNOWN_LOCAL_HTTP_PORTS {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();
            if TcpStream::connect_timeout(&addr, Duration::from_millis(75)).is_ok() {
                found = Some(format!("http://127.0.0.1:{}", port));
                break;
            }
        }
        found
    };
    let lock = PROXY_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((Instant::now(), result.clone()));
    }
    result
}

pub fn detect_active_local_proxy() -> Option<String> {
    let lock = PROXY_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < PROXY_CACHE_TTL {
                return cached.clone();
            }
        }
    }
    detect_active_local_proxy_fresh()
}

fn get_or_build_client(proxy_url: Option<&str>) -> Result<reqwest::Client, String> {
    let key = proxy_url.map(|s| s.to_string());
    let pool = CLIENT_POOL.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = pool.lock() {
        if let Some(existing) = guard.get(&key) {
            return Ok(existing.clone());
        }
    }

    let mut builder = reqwest::Client::builder()
        .user_agent("v2rayN/6.45")
        .connect_timeout(Duration::from_secs(4))
        .pool_max_idle_per_host(4);

    if let Some(p) = proxy_url {
        let proxy = reqwest::Proxy::all(p)
            .map_err(|e| format!("نشانی پروکسی نامعتبر است ({}): {}", p, e))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }

    let built = builder
        .build()
        .map_err(|e| format!("خطا در راه‌اندازی کلاینت شبکه: {}", e))?;

    if let Ok(mut guard) = pool.lock() {
        if guard.len() > 16 {
            guard.clear();
        }
        guard.insert(key, built.clone());
    }
    Ok(built)
}

async fn single_fetch(
    url: &str,
    proxy_url: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    let client = get_or_build_client(proxy_url)?;
    let mut resp = client
        .get(url)
        .timeout(Duration::from_secs(timeout_secs.max(2)))
        .send()
        .await
        .map_err(|e| format!("خطای اتصال به لینک: {}", e))?
        .error_for_status()
        .map_err(|e| format!("پاسخ ناموفق سرور: {}", e))?;

    if let Some(len) = resp.content_length() {
        if len as usize > MAX_HTTP_RESPONSE_BYTES {
            return Err("حجم پاسخ لینک اشتراک بیش از حد مجاز (۸ مگابایت) است.".to_string());
        }
    }

    let mut bytes = Vec::with_capacity(
        resp.content_length()
            .unwrap_or(16_384)
            .min(MAX_HTTP_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("خطا در دریافت محتوای لینک: {}", e))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_HTTP_RESPONSE_BYTES {
            return Err("حجم پاسخ لینک اشتراک بیش از حد مجاز (۸ مگابایت) است.".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&bytes)
        .trim_start_matches('\u{FEFF}')
        .to_string())
}

fn normalize_proxy_input(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("socks") {
        Some(t.to_string())
    } else {
        Some(format!("http://{}", t))
    }
}

pub async fn fetch_text_with_fallback(
    url: &str,
    proxy_mode: &ProxyMode,
    custom_proxy_url: &str,
    timeout_secs: u64,
) -> Result<String, String> {
    let low = url.trim().to_ascii_lowercase();
    if !low.starts_with("http://") && !low.starts_with("https://") {
        return Err("نشانی لینک معتبر (http/https) نیست.".to_string());
    }

    let per_attempt = timeout_secs.clamp(2, 12);

    match proxy_mode {
        ProxyMode::DirectOnly => single_fetch(url, None, per_attempt).await,
        ProxyMode::Custom => {
            if let Some(cp) = normalize_proxy_input(custom_proxy_url) {
                match single_fetch(url, Some(&cp), per_attempt).await {
                    Ok(txt) => Ok(txt),
                    Err(e1) => single_fetch(url, None, per_attempt)
                        .await
                        .map_err(|e2| format!("پروکسی سفارشی ({}) و اتصال مستقیم ناموفق بود: {} | {}", cp, e1, e2)),
                }
            } else {
                single_fetch(url, None, per_attempt).await
            }
        }
        ProxyMode::SystemOrDirect => {
            let sys_proxy = tokio::task::spawn_blocking(read_windows_system_proxy_cached)
                .await
                .ok()
                .flatten();
            if let Some(sp) = sys_proxy {
                match single_fetch(url, Some(&sp), per_attempt).await {
                    Ok(txt) => Ok(txt),
                    Err(_) => single_fetch(url, None, per_attempt).await,
                }
            } else {
                single_fetch(url, None, per_attempt).await
            }
        }
        ProxyMode::AutoDetect => {
            let detected = tokio::task::spawn_blocking(detect_active_local_proxy)
                .await
                .ok()
                .flatten();
            if let Some(lp) = detected {
                match single_fetch(url, Some(&lp), per_attempt).await {
                    Ok(txt) => Ok(txt),
                    Err(_) => single_fetch(url, None, per_attempt).await,
                }
            } else {
                single_fetch(url, None, per_attempt).await
            }
        }
    }
}
