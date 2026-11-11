use crate::models::ProxyMode;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const KNOWN_LOCAL_HTTP_PORTS: &[u16] = &[7890, 7897, 11223, 10809, 12334, 2334, 2081];

#[cfg(target_os = "windows")]
fn read_windows_system_proxy() -> Option<String> {
    use std::process::Command;
    // Fast registry query without requiring extra winreg dep in decryptor-core
    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let enabled = stdout.contains("0x1");
    if !enabled {
        return None;
    }
    let srv_out = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyServer",
        ])
        .output()
        .ok()?;
    let srv_stdout = String::from_utf8_lossy(&srv_out.stdout);
    for line in srv_stdout.lines() {
        if line.contains("ProxyServer") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let val = last.trim();
                if !val.is_empty() {
                    if val.starts_with("http://") || val.starts_with("https://") {
                        return Some(val.to_string());
                    }
                    return Some(format!("http://{}", val));
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn read_windows_system_proxy() -> Option<String> {
    None
}

pub fn detect_active_local_proxy() -> Option<String> {
    if let Ok(env_p) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("HTTP_PROXY")) {
        let trimmed = env_p.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(sys_p) = read_windows_system_proxy() {
        return Some(sys_p);
    }
    for &port in KNOWN_LOCAL_HTTP_PORTS {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        if TcpStream::connect_timeout(&addr, Duration::from_millis(120)).is_ok() {
            return Some(format!("http://127.0.0.1:{}", port));
        }
    }
    None
}

pub async fn fetch_text_with_fallback(
    url: &str,
    proxy_mode: &ProxyMode,
    custom_proxy_url: &str,
    timeout_secs: u64,
) -> Result<String, String> {
    let build_client = |proxy_opt: Option<&str>| -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("ClashMeta/v1.19.0 Mihomo/1.19.0 sing-box/1.14.0 v2rayNG/1.8.5");
        if let Some(p_url) = proxy_opt {
            let proxy = reqwest::Proxy::all(p_url)
                .map_err(|e| format!("آدرس پروکسی نامعتبر است ({}): {}", p_url, e))?;
            builder = builder.proxy(proxy);
        }
        builder.build().map_err(|e| e.to_string())
    };

    let fetch_once = |client: reqwest::Client, target: String| async move {
        let resp = client
            .get(&target)
            .send()
            .await
            .map_err(|e| format!("خطا در اتصال: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!("کد خطای HTTP {}", resp.status().as_u16()));
        }
        resp.text()
            .await
            .map_err(|e| format!("خطا در خواندن پاسخ: {}", e))
    };

    match proxy_mode {
        ProxyMode::DirectOnly => {
            let client = build_client(None)?;
            fetch_once(client, url.to_string()).await
        }
        ProxyMode::Custom => {
            let p = custom_proxy_url.trim();
            if p.is_empty() {
                let client = build_client(None)?;
                fetch_once(client, url.to_string()).await
            } else {
                let full_p = if p.contains("://") {
                    p.to_string()
                } else {
                    format!("http://{}", p)
                };
                let client = build_client(Some(&full_p))?;
                fetch_once(client, url.to_string()).await
            }
        }
        ProxyMode::SystemOrDirect => {
            if let Some(sys_p) = read_windows_system_proxy() {
                if let Ok(client) = build_client(Some(&sys_p)) {
                    if let Ok(txt) = fetch_once(client, url.to_string()).await {
                        return Ok(txt);
                    }
                }
            }
            let direct = build_client(None)?;
            fetch_once(direct, url.to_string()).await
        }
        ProxyMode::AutoDetect => {
            // Try direct first with quick failure or proxy first? If local VPN is running on 7890,
            // GitHub/Cloudflare blocked domains succeed immediately via proxy; try direct first?
            // No, if 7890/system proxy exists, try detected active proxy first, then direct fallback!
            if let Some(proxy_url) = detect_active_local_proxy() {
                if let Ok(client) = build_client(Some(&proxy_url)) {
                    if let Ok(txt) = fetch_once(client, url.to_string()).await {
                        return Ok(txt);
                    }
                }
            }
            let direct = build_client(None)?;
            fetch_once(direct, url.to_string()).await
        }
    }
}
