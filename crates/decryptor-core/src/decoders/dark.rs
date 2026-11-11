use crate::crypto_utils::{base64_decode_safe, decrypt_aes_cfb};
use crate::models::{DecryptionError, DnsCompanionEntry, ProxyProfile};
use regex::Regex;
use rmpv::Value as MsgVal;
use serde_json::{Map, Value as JsonVal};

const DT_KEY_256: &[u8] = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd";
const DT_KEY_192: &[u8] = b"F)J@NcRfUjXn2r4u7x!A%D*G";
const DT_IV: [u8; 16] = [
    0x23, 0x2e, 0x39, 0x18, 0x55, 0x23, 0x18, 0x4a, 0x57, 0x23, 0x58, 0x62, 0x42, 0x20, 0x0e, 0x05,
];

fn msgpack_to_json(val: &MsgVal) -> JsonVal {
    match val {
        MsgVal::Nil => JsonVal::Null,
        MsgVal::Boolean(b) => JsonVal::Bool(*b),
        MsgVal::Integer(i) => {
            if let Some(u) = i.as_u64() {
                JsonVal::Number(u.into())
            } else if let Some(s) = i.as_i64() {
                JsonVal::Number(s.into())
            } else {
                JsonVal::Null
            }
        }
        MsgVal::F32(f) => serde_json::Number::from_f64(*f as f64)
            .map(JsonVal::Number)
            .unwrap_or(JsonVal::Null),
        MsgVal::F64(f) => serde_json::Number::from_f64(*f)
            .map(JsonVal::Number)
            .unwrap_or(JsonVal::Null),
        MsgVal::String(s) => JsonVal::String(s.as_str().unwrap_or("").to_string()),
        MsgVal::Binary(b) => JsonVal::Object({
            let mut m = Map::new();
            m.insert("type".to_string(), JsonVal::String("Buffer".to_string()));
            m.insert(
                "data".to_string(),
                JsonVal::Array(b.iter().map(|&byte| JsonVal::Number(byte.into())).collect()),
            );
            m
        }),
        MsgVal::Array(arr) => JsonVal::Array(arr.iter().map(msgpack_to_json).collect()),
        MsgVal::Map(pairs) => {
            let mut m = Map::new();
            for (k, v) in pairs {
                let key_str = match k {
                    MsgVal::String(s) => s.as_str().unwrap_or("").to_string(),
                    other => format!("{}", other),
                };
                m.insert(key_str, msgpack_to_json(v));
            }
            JsonVal::Object(m)
        }
        MsgVal::Ext(_, b) => JsonVal::Array(b.iter().map(|&byte| JsonVal::Number(byte.into())).collect()),
    }
}

fn safe_msgpack_decode(data: &[u8]) -> Option<JsonVal> {
    for trim in 0..20 {
        if trim >= data.len() {
            break;
        }
        let mut slice = &data[..data.len() - trim];
        if let Ok(v) = rmpv::decode::read_value(&mut slice) {
            return Some(msgpack_to_json(&v));
        }
    }
    None
}

fn extract_buffer_bytes(v: &JsonVal) -> Option<Vec<u8>> {
    match v {
        JsonVal::String(s) => base64_decode_safe(s).ok(),
        JsonVal::Object(m) => {
            if let Some(JsonVal::Array(arr)) = m.get("data") {
                Some(
                    arr.iter()
                        .filter_map(|x| x.as_u64().map(|n| n as u8))
                        .collect(),
                )
            } else {
                None
            }
        }
        JsonVal::Array(arr) => Some(
            arr.iter()
                .filter_map(|x| x.as_u64().map(|n| n as u8))
                .collect(),
        ),
        _ => None,
    }
}

fn clean_encrypted(val: JsonVal) -> JsonVal {
    match val {
        JsonVal::Array(arr) => JsonVal::Array(arr.into_iter().map(clean_encrypted).collect()),
        JsonVal::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if let Some(stripped) = k.strip_prefix("Encrypted") {
                    if let Some(buf) = extract_buffer_bytes(&v) {
                        if let Ok(dec) = decrypt_aes_cfb(&buf, DT_KEY_192, &DT_IV) {
                            let s = String::from_utf8_lossy(&dec).into_owned();
                            let decoded_val = serde_json::from_str::<JsonVal>(&s)
                                .unwrap_or(JsonVal::String(s));
                            out.insert(stripped.to_string(), decoded_val);
                            continue;
                        }
                    }
                }
                out.insert(k, clean_encrypted(v));
            }
            JsonVal::Object(out)
        }
        other => other,
    }
}

pub struct DarkDecoded {
    pub parsed: JsonVal,
    pub profiles: Vec<ProxyProfile>,
    pub dns_companions: Vec<DnsCompanionEntry>,
}

pub fn decrypt_dark(raw_input: &str) -> Result<DarkDecoded, DecryptionError> {
    let mut text = raw_input.trim();
    if let Some(rest) = text.strip_prefix("darktunnel://") {
        text = rest.trim();
    }
    let outer_bytes = base64_decode_safe(text).map_err(|_| {
        DecryptionError::plain("قالب فایل DarkTunnel نامعتبر است (Base64 نامعتبر).")
    })?;
    let mut outer_obj: JsonVal = serde_json::from_slice(&outer_bytes).map_err(|_| {
        DecryptionError::plain("قالب فایل DarkTunnel نامعتبر است (JSON بیرونی شناسایی نشد).")
    })?;

    let enc_locked_opt = outer_obj
        .get("encryptedLockedConfig")
        .or_else(|| outer_obj.get("EncryptedLockedConfig"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let Some(enc_locked_str) = enc_locked_opt else {
        return Ok(DarkDecoded {
            parsed: outer_obj,
            profiles: Vec::new(),
            dns_companions: Vec::new(),
        });
    };

    let enc_bytes = base64_decode_safe(&enc_locked_str)
        .map_err(|_| DecryptionError::plain("رمزگشایی لایه اول DarkTunnel ناموفق بود."))?;
    let dec_outer = decrypt_aes_cfb(&enc_bytes, DT_KEY_256, &DT_IV)
        .map_err(|_| DecryptionError::plain("رمزگشایی لایه اول DarkTunnel ناموفق بود."))?;
    let mut unpacked = safe_msgpack_decode(&dec_outer)
        .ok_or_else(|| DecryptionError::plain("رمزگشایی لایه اول DarkTunnel ناموفق بود."))?;

    if let Some(inner_v) = unpacked.get("EncryptedLockedConfig").cloned() {
        if let Some(inner_bytes) = extract_buffer_bytes(&inner_v) {
            if let Ok(dec_inner) = decrypt_aes_cfb(&inner_bytes, DT_KEY_192, &DT_IV) {
                if let Some(unpacked_inner) = safe_msgpack_decode(&dec_inner) {
                    if let Some(obj) = unpacked.as_object_mut() {
                        obj.insert(
                            "EncryptedLockedConfig".to_string(),
                            clean_encrypted(unpacked_inner),
                        );
                    }
                }
            }
        }
    }

    if let Some(obj) = outer_obj.as_object_mut() {
        obj.insert("encryptedLockedConfig".to_string(), unpacked.clone());
    }

    let base_name = outer_obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("DarkTunnel")
        .to_string();

    let mut profiles = Vec::new();
    let mut dns_companions = Vec::new();
    let enc_inner = unpacked
        .get("EncryptedLockedConfig")
        .unwrap_or(&JsonVal::Null);

    if let Some(v2cfg) = enc_inner
        .get("V2RayConfig")
        .and_then(|v| v.get("Config"))
        .and_then(|v| v.as_str())
    {
        if v2cfg.contains("://") {
            let re = Regex::new(r"(?i)(?:vless|vmess|trojan|ss)://[^\s]+").unwrap();
            if let Some(m) = re.find(v2cfg) {
                profiles.push(ProxyProfile {
                    name: format!("{}-V2ray", base_name),
                    protocol: "v2ray_uri".to_string(),
                    raw_uri: Some(m.as_str().to_string()),
                    ..Default::default()
                });
            }
        }
    }

    if let Some(ssh) = enc_inner.get("SshConfig").and_then(|v| v.as_object()) {
        if let Some(host) = ssh.get("Host").and_then(|v| v.as_str()) {
            let h = host.trim().to_string();
            if !h.is_empty() {
                let port = ssh
                    .get("Port")
                    .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(22) as u16;
                let username = ssh
                    .get("Username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let password = ssh
                    .get("Password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                dns_companions.push(DnsCompanionEntry {
                    kind: "ssh".to_string(),
                    title: "DarkTunnel SSH Profile".to_string(),
                    summary: format!(
                        "🖥 سرور SSH: {}:{}\n👤 نام کاربری: {}\n🔑 رمز عبور: {}",
                        h, port, username, password
                    ),
                });
                profiles.push(ProxyProfile {
                    name: format!("{}-SSH", base_name),
                    protocol: "ssh".to_string(),
                    server: h,
                    server_port: port,
                    username,
                    password,
                    ..Default::default()
                });
            }
        }
    }

    if profiles.is_empty() {
        if let Some(inj) = enc_inner.get("InjectConfig").and_then(|v| v.as_object()) {
            let host = inj
                .get("ProxyHost")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let port = inj
                .get("ProxyPort")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(8880) as u16;
            let is_website = Regex::new(
                r"(?i)^(?:chat\.openai\.com|openai\.com|google\.com|apple\.com|t\.me|telegram\.org)$",
            )
            .unwrap()
            .is_match(&host);
            if !host.is_empty() && port > 0 && !is_website {
                profiles.push(ProxyProfile {
                    name: format!("{}-Proxy", base_name),
                    protocol: "http".to_string(),
                    server: host,
                    server_port: port,
                    ..Default::default()
                });
            }
        }
    }

    Ok(DarkDecoded {
        parsed: outer_obj,
        profiles,
        dns_companions,
    })
}
