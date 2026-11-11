use crate::crypto_utils::chacha20_legacy_xor;
use crate::models::{DecryptionError, ProxyProfile};
use regex::Regex;
use serde_json::{Map, Value};

const FIXED_NONCE: [u8; 8] = [0x74, 0xd0, 0xf3, 0x87, 0x9f, 0x9d, 0x47, 0xf7];
const L1_KEY: [u8; 32] = [
    0xc8, 0xa6, 0xa8, 0xea, 0x10, 0x2d, 0x5a, 0x0b, 0xaf, 0x8f, 0xdb, 0x1b, 0x39, 0xcd, 0x61, 0x5c,
    0x0d, 0x07, 0xc1, 0xed, 0xcb, 0xde, 0x4e, 0x82, 0xcf, 0xdd, 0x30, 0x9b, 0xc4, 0x58, 0x7f, 0x6b,
];
const L2_KEY: [u8; 32] = [
    0x7f, 0x9d, 0xb4, 0x8f, 0xfd, 0xe4, 0x49, 0xad, 0x19, 0xf9, 0xed, 0x44, 0xb8, 0xb2, 0x7e, 0xee,
    0x33, 0x4a, 0xb4, 0xa8, 0x5b, 0x97, 0x2d, 0xca, 0x8f, 0xf2, 0x0e, 0x4e, 0x8e, 0xd4, 0x4e, 0x4e,
];
const L3_KEY: [u8; 32] = [
    0xd3, 0x93, 0x94, 0x51, 0x7a, 0x48, 0x97, 0x1f, 0x6e, 0x85, 0x55, 0xe9, 0x94, 0xbe, 0xe5, 0xbd,
    0x83, 0x5e, 0x5a, 0xb2, 0xf8, 0x5f, 0xbd, 0x76, 0xbb, 0xd9, 0x98, 0x00, 0xf3, 0x2b, 0x96, 0x7e,
];

fn map_key(k: &str) -> &str {
    match k {
        "a" => "CONFIGS",
        "b" => "NOTE",
        "c" => "EXPIRY_DATE",
        "e" => "CONFIGNAME",
        "f" => "PAYLOAD_ENABLED",
        "g" => "PAYLOAD",
        "h" => "PROXY",
        "i" => "PROXY_PORT",
        "j" => "TYPE",
        "k" => "PROXY_ENABLED",
        "l" => "ADDRESS",
        "m" => "PORT",
        "n" => "IS_PREMIUM",
        "o" => "USERNAME",
        "p" => "PASSWORD",
        "q" => "TIMEOUT",
        "r" => "PROTOCOL",
        "s" => "VERSION",
        "t" => "ENCRYPTION",
        "u" => "COMPRESSIONLEVEL",
        "v" => "DNS",
        "w" => "NSSERVER",
        "x" => "PUBKEY",
        "y" => "ISDEFAULT",
        "z" => "LOCALPORT",
        other => other,
    }
}

fn is_encrypted_field(k: &str) -> bool {
    matches!(k, "g" | "h" | "l" | "o" | "p" | "v" | "x" | "i" | "w")
}

fn derive_inner_nonce(user_key: &str) -> Option<[u8; 8]> {
    if user_key.len() != 32 {
        return None;
    }
    let part1: String = user_key[16..32].chars().rev().collect();
    let part2 = &user_key[0..16];
    let hex_str: String = format!("{}68{}", part1, part2).chars().take(16).collect();
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() == 8 {
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Some(out)
    } else {
        None
    }
}

fn clean_c_string(buf: &[u8]) -> String {
    if buf.is_empty() {
        return String::new();
    }
    let slice = match buf.iter().position(|&b| b == 0) {
        Some(idx) => &buf[..idx],
        None => buf,
    };
    let s = String::from_utf8_lossy(slice);
    s.chars()
        .filter(|&c| {
            let code = c as u32;
            (0x20..=0x7e).contains(&code) || (0x0600..=0x06ff).contains(&code)
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn sanitize_field(key: &str, val: Value) -> Value {
    let Value::String(s) = val else {
        return val;
    };
    let clean: String = s.chars().filter(|&c| (c as u32) >= 0x20 && (c as u32) != 0x7f).collect();
    let trimmed = clean.trim().to_string();
    if matches!(key, "ADDRESS" | "DNS" | "PROXY" | "NSSERVER") {
        let ip_re = Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?").unwrap();
        if let Some(m) = ip_re.find(&trimmed) {
            return Value::String(m.as_str().to_string());
        }
        return Value::String(
            trimmed
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
                .collect(),
        );
    }
    if matches!(key, "USERNAME" | "PASSWORD") {
        let cred_re = Regex::new(r"^[a-zA-Z0-9!@#$%^&*()._-]+").unwrap();
        if let Some(m) = cred_re.find(&trimmed) {
            return Value::String(m.as_str().to_string());
        }
    }
    Value::String(trimmed)
}

fn extract_json(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(&text[start..=end]) {
        return Some(v);
    }
    for (idx, _) in text.rmatch_indices('}') {
        if idx > start {
            if let Ok(v) = serde_json::from_str::<Value>(&text[start..=idx]) {
                return Some(v);
            }
        }
    }
    None
}

pub struct SscDecoded {
    pub profiles: Vec<ProxyProfile>,
    pub expiry_raw: Option<String>,
}

pub fn decrypt_ssc(raw_input: &str, file_name: &str) -> Result<SscDecoded, DecryptionError> {
    let mut content = raw_input.trim().to_string();
    if let Some(rest) = content.strip_prefix("ssc://") {
        content = rest.chars().rev().collect();
    }
    let cipher_hex: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    if cipher_hex.len() % 2 != 0 || cipher_hex.is_empty() {
        return Err(DecryptionError::plain("طول رشته هگز کانفیگ SSC نامعتبر است."));
    }
    let cipher_bytes = hex::decode(&cipher_hex)
        .map_err(|_| DecryptionError::plain("رشته هگز کانفیگ SSC نامعتبر است."))?;

    let l1_data = chacha20_legacy_xor(&L1_KEY, &FIXED_NONCE, &cipher_bytes, 1)
        .map_err(DecryptionError::plain)?;
    let l1_json = extract_json(&String::from_utf8_lossy(&l1_data))
        .ok_or_else(|| DecryptionError::plain("رمزگشایی لایه اول SSC ناموفق بود."))?;

    let target_json: Option<Value> = if let (Some(c_hex), Some(a_str)) = (
        l1_json.get("c").and_then(|v| v.as_str()),
        l1_json.get("a").and_then(|v| v.as_str()),
    ) {
        let a_prefix: String = a_str.chars().take(16).collect();
        let l2_nonce = hex::decode(&a_prefix).map_err(|_| {
            DecryptionError::plain("رمزگشایی لایه دوم پیکربندی SSC ناموفق بود.")
        })?;
        let l2_cipher = hex::decode(c_hex).map_err(|_| {
            DecryptionError::plain("رمزگشایی لایه دوم پیکربندی SSC ناموفق بود.")
        })?;
        let l2_data = chacha20_legacy_xor(&L2_KEY, &l2_nonce, &l2_cipher, 1)
            .map_err(DecryptionError::plain)?;
        extract_json(&String::from_utf8_lossy(&l2_data))
    } else if l1_json.get("a").and_then(|v| v.as_array()).is_some() {
        Some(l1_json)
    } else {
        None
    };

    let target = target_json
        .ok_or_else(|| DecryptionError::plain("رمزگشایی لایه دوم پیکربندی SSC ناموفق بود."))?;

    let config_list: Vec<Value> = if let Some(arr) = target.get("a").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = target.get("CONFIGS").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        vec![target]
    };

    let base_name = file_name.trim_end_matches(".ssc").trim_end_matches(".SSC");
    let mut profiles = Vec::new();
    let mut first_expiry: Option<String> = None;

    for (idx, item_val) in config_list.into_iter().enumerate() {
        let Some(mut item_map) = item_val.as_object().cloned() else {
            continue;
        };
        let inner_nonce = item_map
            .get("b")
            .and_then(|v| v.as_str())
            .and_then(derive_inner_nonce);

        if let Some(nonce) = inner_nonce {
            let keys: Vec<String> = item_map.keys().cloned().collect();
            for k in keys {
                if is_encrypted_field(&k) {
                    if let Some(hex_val) = item_map.get(&k).and_then(|v| v.as_str()) {
                        if hex_val.len() > 16 {
                            if let Ok(enc_bytes) = hex::decode(hex_val) {
                                if let Ok(dec) = chacha20_legacy_xor(&L3_KEY, &nonce, &enc_bytes, 1) {
                                    let plain = clean_c_string(&dec);
                                    if !plain.is_empty() {
                                        item_map.insert(k, Value::String(plain));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut readable = Map::new();
        for (k, v) in item_map {
            let mapped = map_key(&k).to_string();
            let clean_v = sanitize_field(&mapped, v);
            readable.insert(mapped, clean_v);
        }

        if first_expiry.is_none() {
            if let Some(exp) = readable.get("EXPIRY_DATE") {
                if !exp.is_null() {
                    let s = match exp {
                        Value::String(st) => st.clone(),
                        Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    if !s.is_empty() {
                        first_expiry = Some(s);
                    }
                }
            }
        }

        let get_str = |k: &str| {
            readable
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        let server = if !get_str("ADDRESS").is_empty() {
            get_str("ADDRESS")
        } else {
            get_str("PROXY")
        };
        if server.is_empty() {
            continue;
        }
        let port = readable
            .get("PORT")
            .or_else(|| readable.get("PROXY_PORT"))
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(22) as u16;
        let config_name = {
            let n = get_str("CONFIGNAME");
            if n.is_empty() {
                format!("{}-{}", base_name, idx + 1)
            } else {
                n
            }
        };

        profiles.push(ProxyProfile {
            protocol: "ssh".to_string(),
            name: config_name,
            server,
            server_port: port,
            username: get_str("USERNAME"),
            password: get_str("PASSWORD"),
            public_key: get_str("PUBKEY"),
            payload: Some(get_str("PAYLOAD")).filter(|s| !s.is_empty()),
            dns: {
                let d = get_str("DNS");
                if d.is_empty() { Vec::new() } else { vec![d] }
            },
            ..Default::default()
        });
    }

    Ok(SscDecoded {
        profiles,
        expiry_raw: first_expiry,
    })
}
