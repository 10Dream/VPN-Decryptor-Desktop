use crate::crypto_utils::{base64_decode_safe, decrypt_aes_ecb};
use crate::models::{DecryptionError, ProxyProfile};
use regex::Regex;
use serde_json::Value;
use sha1::{Digest, Sha1};

const HAT_IMPORT_KEY: &[u8] = b"8515D40BD04D8C97";

pub struct HatDecoded {
    pub parsed: Value,
    pub profiles: Vec<ProxyProfile>,
}

pub fn decrypt_hat(raw_input: &str) -> Result<HatDecoded, DecryptionError> {
    let text = raw_input.trim();
    let ciphertext = base64_decode_safe(text).map_err(|e| {
        DecryptionError::plain(format!("رمزگشایی HA Tunnel Plus ناموفق بود: {}", e))
    })?;

    let mut hasher = Sha1::new();
    hasher.update(HAT_IMPORT_KEY);
    let digest = hasher.finalize();
    let derived_key = &digest[0..16];

    let plaintext = decrypt_aes_ecb(&ciphertext, derived_key, true).map_err(|e| {
        DecryptionError::plain(format!("رمزگشایی HA Tunnel Plus ناموفق بود: {}", e))
    })?;
    let str_text = String::from_utf8_lossy(&plaintext).into_owned();
    let parsed: Value = serde_json::from_str(&str_text).unwrap_or(Value::String(str_text));

    let mut profiles = Vec::new();
    if parsed.is_object() {
        let p = parsed
            .get("profilev5")
            .or_else(|| parsed.get("profile"))
            .unwrap_or(&Value::Null);
        let server_raw = p.get("primary_host").and_then(|v| v.as_str()).unwrap_or("");
        let server: String = server_raw
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\t' | ' '))
            .collect();
        let port = p
            .get("server_port")
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(80) as u16;

        let bug_re = Regex::new(
            r"(?i)\.(?:ac\.ir|gov\.ir|org\.ir|ir|blogstar\.net|telewebion\.com|digikala\.com|snapp\.ir|rubika\.ir)$",
        )
        .unwrap();
        let ip_re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
        let is_ip = ip_re.is_match(&server);
        let is_bug = bug_re.is_match(&server);

        if !server.is_empty() && (is_ip || !is_bug) {
            let realm = p.get("realm_host").and_then(|v| v.as_str()).unwrap_or("");
            let clean_sni: String = (if realm.is_empty() { &server } else { realm })
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\t' | ' '))
                .collect();
            let raw_name = parsed
                .get("descriptionv5")
                .or_else(|| parsed.get("description"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(if clean_sni.is_empty() {
                    "HAT-Proxy"
                } else {
                    &clean_sni
                });
            let name = raw_name
                .replace(['\r', '\n', '\t'], " ")
                .trim()
                .to_string();

            profiles.push(ProxyProfile {
                protocol: "http".to_string(),
                name,
                server: server.clone(),
                server_port: port,
                tls: port == 443,
                sni: if clean_sni.is_empty() {
                    server.clone()
                } else {
                    clean_sni.clone()
                },
                host: if clean_sni.is_empty() {
                    server
                } else {
                    clean_sni
                },
                ..Default::default()
            });
        }
    }

    Ok(HatDecoded { parsed, profiles })
}
