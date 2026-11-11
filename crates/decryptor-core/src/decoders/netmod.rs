use crate::crypto_utils::{base64_decode_safe, decrypt_aes_ecb};
use crate::models::{DecryptionError, DnsCompanionEntry, ProxyProfile};
use serde_json::Value;

const NETMOD_KEYS: [&[u8]; 3] = [
    b"<n3t5yn4^n3tm0d>",
    b"_netsyna_netmod_",
    b"nicetrybuddygoon",
];

pub struct NetModDecoded {
    pub parsed: Value,
    pub profiles: Vec<ProxyProfile>,
    pub dns_companions: Vec<DnsCompanionEntry>,
}

pub fn decrypt_netmod(raw_input: &str) -> Result<NetModDecoded, DecryptionError> {
    let mut text = raw_input.trim();
    if let Some(idx) = text.find("://") {
        let scheme = &text[..idx];
        if scheme.to_lowercase().starts_with("nm-") {
            text = text[idx + 3..].trim();
        }
    }

    let ciphertext = base64_decode_safe(text).map_err(|_| {
        DecryptionError::plain("رمزگشایی NetMod با هیچ‌یک از کلیدهای استاندارد موفق نبود.")
    })?;

    for key in NETMOD_KEYS {
        let Ok(pt) = decrypt_aes_ecb(&ciphertext, key, true) else {
            continue;
        };
        let s = String::from_utf8_lossy(&pt).into_owned();
        let parsed: Option<Value> = serde_json::from_str(&s).ok();

        if parsed.is_none() {
            let prefix: String = s.chars().take(50).collect();
            let printable = !prefix.is_empty()
                && prefix
                    .chars()
                    .all(|c| (c >= ' ' && c <= '~') || matches!(c, '\r' | '\n' | '\t'));
            if !printable {
                continue;
            }
        }

        let mut profiles = Vec::new();
        let mut dns_companions = Vec::new();

        if let Some(ref obj) = parsed {
            if let Some(common) = obj.get("Common").and_then(|v| v.as_array()) {
                for item in common {
                    if !item.is_object() {
                        continue;
                    }
                    let proto_name = item
                        .get("Protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("vless")
                        .to_lowercase();
                    let host_name = item.get("Hostname").and_then(|v| v.as_str()).unwrap_or("");
                    let remark = item
                        .get("Remark")
                        .and_then(|v| v.as_str())
                        .filter(|x| !x.is_empty())
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| {
                            format!(
                                "{}-{}",
                                proto_name.to_uppercase(),
                                if host_name.is_empty() {
                                    "Server"
                                } else {
                                    host_name
                                }
                            )
                        });
                    let port = item
                        .get("Port")
                        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                        .unwrap_or(443) as u16;
                    let uid = item.get("UserID").and_then(|v| v.as_str()).unwrap_or("");
                    let flow = item
                        .get("Flow")
                        .and_then(|v| v.as_str())
                        .filter(|&f| !f.is_empty() && f != "none")
                        .unwrap_or("");
                    let host = item.get("Host").and_then(|v| v.as_str()).unwrap_or("");
                    let sni = item
                        .get("SNI")
                        .and_then(|v| v.as_str())
                        .filter(|x| !x.is_empty())
                        .or(if !host.is_empty() { Some(host) } else { None })
                        .unwrap_or(host_name);
                    let is_tls = item.get("TLSType").and_then(|v| v.as_str()) == Some("tls");
                    let alpn = item
                        .get("Alpn")
                        .and_then(|v| v.as_str())
                        .map(|a| {
                            a.split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();

                    profiles.push(ProxyProfile {
                        name: remark,
                        protocol: proto_name,
                        server: host_name.to_string(),
                        server_port: port,
                        uuid: uid.to_string(),
                        password: uid.to_string(),
                        flow: flow.to_string(),
                        network: item
                            .get("TransferProtocol")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tcp")
                            .to_lowercase(),
                        path: item.get("Path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        host: host.to_string(),
                        sni: sni.to_string(),
                        tls: is_tls,
                        security: if is_tls { "tls" } else { "none" }.to_string(),
                        fingerprint: item
                            .get("FingerPrint")
                            .and_then(|v| v.as_str())
                            .filter(|x| !x.is_empty())
                            .unwrap_or("chrome")
                            .to_string(),
                        alpn,
                        ..Default::default()
                    });
                }
            }

            if let Some(proxies) = obj.get("Proxy").and_then(|v| v.as_array()) {
                for item in proxies {
                    let Some(host) = item.get("Host").and_then(|v| v.as_str()).filter(|x| !x.is_empty()) else {
                        continue;
                    };
                    let port = item
                        .get("Port")
                        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                        .unwrap_or(8080) as u16;
                    let name = item
                        .get("Remark")
                        .and_then(|v| v.as_str())
                        .filter(|x| !x.is_empty())
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| format!("Proxy-{}:{}", host, port));
                    profiles.push(ProxyProfile {
                        name,
                        protocol: "http".to_string(),
                        server: host.to_string(),
                        server_port: port,
                        username: item.get("User").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        password: item.get("Pass").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        ..Default::default()
                    });
                }
            }

            if let Some(ssh_arr) = obj.get("SSH").and_then(|v| v.as_array()) {
                for item in ssh_arr {
                    let Some(host) = item.get("Host").and_then(|v| v.as_str()).filter(|x| !x.is_empty()) else {
                        continue;
                    };
                    let port = item
                        .get("Port")
                        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                        .unwrap_or(22) as u16;
                    let user = item.get("User").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let pass = item.get("Pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = item
                        .get("Remark")
                        .and_then(|v| v.as_str())
                        .filter(|x| !x.is_empty())
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| format!("SSH-{}:{}", host, port));

                    dns_companions.push(DnsCompanionEntry {
                        kind: "ssh".to_string(),
                        title: name.clone(),
                        summary: format!(
                            "🖥 سرور SSH: {}:{}\n👤 نام کاربری: {}\n🔑 رمز عبور: {}",
                            host, port, user, pass
                        ),
                    });
                    profiles.push(ProxyProfile {
                        name,
                        protocol: "ssh".to_string(),
                        server: host.to_string(),
                        server_port: port,
                        username: user,
                        password: pass,
                        ..Default::default()
                    });
                }
            }

            if let Some(v) = obj.get("V2ray").and_then(|x| x.as_object()) {
                let proto_name = v
                    .get("Type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("vless")
                    .to_lowercase();
                let addr = obj.get("Address").and_then(|x| x.as_str()).unwrap_or("");
                let name = obj
                    .get("Remarks")
                    .and_then(|x| x.as_str())
                    .filter(|x| !x.is_empty())
                    .or(if !addr.is_empty() { Some(addr) } else { None })
                    .unwrap_or("NetMod-V2ray")
                    .to_string();
                let port = obj
                    .get("Port")
                    .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(443) as u16;
                let uid = v.get("UUID").and_then(|x| x.as_str()).unwrap_or("");
                let host = v.get("Host").and_then(|x| x.as_str()).unwrap_or("");
                let sni = v
                    .get("SNI")
                    .and_then(|x| x.as_str())
                    .filter(|x| !x.is_empty())
                    .unwrap_or(host);
                let tls = v.get("TLS").and_then(|x| x.as_bool()).unwrap_or(false);

                profiles.push(ProxyProfile {
                    name,
                    protocol: proto_name,
                    server: addr.to_string(),
                    server_port: port,
                    uuid: uid.to_string(),
                    password: uid.to_string(),
                    network: v
                        .get("Transport")
                        .and_then(|x| x.as_str())
                        .unwrap_or("tcp")
                        .to_lowercase(),
                    host: host.to_string(),
                    sni: sni.to_string(),
                    tls,
                    security: if tls { "tls" } else { "none" }.to_string(),
                    ..Default::default()
                });
            }
        }

        return Ok(NetModDecoded {
            parsed: parsed.unwrap_or(Value::String(s)),
            profiles,
            dns_companions,
        });
    }

    Err(DecryptionError::plain(
        "رمزگشایی NetMod با هیچ‌یک از کلیدهای استاندارد موفق نبود.",
    ))
}
