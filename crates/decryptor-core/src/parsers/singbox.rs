use crate::models::{DecryptionError, ProxyProfile};
use serde_json::Value;

fn str_field(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

pub fn parse_singbox_json(raw_text: &str, _file_name: &str) -> Result<Vec<ProxyProfile>, DecryptionError> {
    let data: Value = serde_json::from_str(raw_text.trim()).map_err(|_| {
        DecryptionError::plain("قالب فایل Sing-box نامعتبر است (JSON معتبر یافت نشد).")
    })?;

    let mut outbounds: Vec<Value> = if let Some(arr) = data.as_array() {
        arr.clone()
    } else if let Some(arr) = data.get("outbounds").and_then(|v| v.as_array()) {
        arr.clone()
    } else if data.get("type").is_some() && data.get("server").is_some() {
        vec![data.clone()]
    } else {
        return Err(DecryptionError::plain(
            "هیچ بخش outbounds معتبری در فایل Sing-box یافت نشد.",
        ));
    };

    // Also include WireGuard endpoints if Sing-box 1.11+ format
    if let Some(endpoints) = data.get("endpoints").and_then(|v| v.as_array()) {
        outbounds.extend(endpoints.iter().cloned());
    }

    let mut profiles = Vec::new();
    for o in outbounds {
        let typ = str_field(o.get("type").or_else(|| o.get("protocol"))).to_lowercase();
        if matches!(typ.as_str(), "direct" | "block" | "dns" | "selector" | "urltest" | "") {
            continue;
        }

        // Endpoint style WireGuard support
        if typ == "wireguard" && o.get("server").is_none() {
            let Some(peer) = o.get("peers").and_then(|p| p.as_array()).and_then(|a| a.first()) else {
                continue;
            };
            let srv = str_field(peer.get("address"));
            if srv.is_empty() { continue; }
            let port = peer.get("port").and_then(|p| p.as_u64()).unwrap_or(51820) as u16;
            let addr = o.get("address").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|x| x.as_str()).unwrap_or("172.16.0.2/32");
            let reserved = peer.get("reserved").and_then(|v| v.as_array()).map(|a| {
                a.iter().filter_map(|x| x.as_i64().map(|n| n as i32)).collect::<Vec<_>>()
            });
            profiles.push(ProxyProfile {
                name: str_field(o.get("tag").or_else(|| o.get("name"))),
                protocol: "wireguard".to_string(),
                server: srv,
                server_port: port,
                private_key: str_field(o.get("private_key")),
                public_key: str_field(peer.get("public_key")),
                preshared_key: str_field(peer.get("pre_shared_key")),
                local_address: addr.to_string(),
                reserved,
                mtu: o.get("mtu").and_then(|m| m.as_u64()).map(|m| m as u32),
                ..Default::default()
            });
            continue;
        }

        let server = str_field(o.get("server"));
        if server.is_empty() {
            continue;
        }

        let tls_obj = o.get("tls").unwrap_or(&Value::Null);
        let reality_obj = tls_obj.get("reality").unwrap_or(&Value::Null);
        let transport_obj = o.get("transport").unwrap_or(&Value::Null);
        let net = str_field(transport_obj.get("type")).to_lowercase();
        let net_final = if net.is_empty() { "tcp".to_string() } else { net };

        let ws_path = str_field(transport_obj.get("path"));
        let ws_host = str_field(
            transport_obj
                .get("headers")
                .and_then(|h| h.get("Host"))
                .or_else(|| transport_obj.get("host")),
        );
        let tls_enabled = tls_obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        let reality_enabled = reality_obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        let sni = str_field(tls_obj.get("server_name"));
        let fp = str_field(tls_obj.get("utls").and_then(|u| u.get("fingerprint")));
        let sid = match reality_obj.get("short_id") {
            Some(Value::Array(arr)) => arr.first().and_then(|x| x.as_str()).unwrap_or("").to_string(),
            other => str_field(other),
        };
        let proto = if typ == "ss" { "shadowsocks".to_string() } else { typ.clone() };
        let name = {
            let n = str_field(o.get("tag").or_else(|| o.get("name")));
            if n.is_empty() {
                format!("{}-{}", proto.to_uppercase(), server)
            } else {
                n
            }
        };

        let alpn = tls_obj
            .get("alpn")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        profiles.push(ProxyProfile {
            name,
            protocol: proto.clone(),
            server,
            server_port: o.get("server_port").and_then(|v| v.as_u64()).unwrap_or(443) as u16,
            uuid: str_field(o.get("uuid").or_else(|| o.get("password"))),
            password: str_field(o.get("password").or_else(|| o.get("uuid"))),
            username: str_field(o.get("user").or_else(|| o.get("username"))),
            flow: str_field(o.get("flow")),
            encryption: {
                let e = str_field(o.get("encryption"));
                if e.is_empty() { "none".to_string() } else { e }
            },
            network: net_final,
            path: ws_path,
            host: if !ws_host.is_empty() { ws_host } else { sni.clone() },
            service_name: str_field(transport_obj.get("service_name")),
            security: if reality_enabled {
                "reality".to_string()
            } else if tls_enabled {
                "tls".to_string()
            } else {
                "none".to_string()
            },
            tls: tls_enabled,
            reality: reality_enabled,
            sni,
            fingerprint: if fp.is_empty() { "chrome".to_string() } else { fp },
            public_key: str_field(reality_obj.get("public_key")),
            short_id: sid,
            alpn,
            skip_cert_verify: tls_obj.get("insecure").and_then(|v| v.as_bool()).unwrap_or(false),
            method: str_field(o.get("method")),
            cipher: str_field(o.get("method").or_else(|| o.get("security"))),
            alter_id: o.get("alter_id").and_then(|v| v.as_u64()).map(|n| n as u32),
            auth_str: str_field(o.get("auth_str").or_else(|| o.get("auth").or_else(|| o.get("password")))),
            obfs: str_field(o.get("obfs").and_then(|ob| ob.get("type"))),
            obfs_password: str_field(o.get("obfs").and_then(|ob| ob.get("password"))),
            congestion_control: o.get("congestion_control").and_then(|v| v.as_str()).map(|s| s.to_string()),
            udp_relay_mode: o.get("udp_relay_mode").and_then(|v| v.as_str()).map(|s| s.to_string()),
            server_public_key: o.get("server_public_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
            server_disco_key: o.get("server_disco_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
            derp_map_url: o.get("derp_map_url").and_then(|v| v.as_str()).map(|s| s.to_string()),
            ..Default::default()
        });
    }

    if profiles.is_empty() {
        return Err(DecryptionError::plain(
            "هیچ سرور پروکسی قابل استفاده‌ای در فایل Sing-box یافت نشد.",
        ));
    }

    Ok(profiles)
}
