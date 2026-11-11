use crate::models::{AmneziaWgOptions, DecryptionError, ProxyProfile};
use std::collections::BTreeMap;

pub fn parse_wireguard_conf(raw_text: &str, file_name: &str) -> Result<ProxyProfile, DecryptionError> {
    let mut section = String::new();
    let mut iface: BTreeMap<String, String> = BTreeMap::new();
    let mut peer: BTreeMap<String, String> = BTreeMap::new();
    let mut custom_name = String::new();

    for raw_line in raw_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            let trimmed_comment = line[1..].trim();
            if let Some((k, v)) = trimmed_comment.split_once('=') {
                if k.trim().eq_ignore_ascii_case("name") {
                    custom_name = v.trim().to_string();
                }
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_lowercase();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if section == "interface" {
                iface.insert(key, val);
            } else if section == "peer" {
                peer.insert(key, val);
            }
        }
    }

    if !iface.contains_key("privatekey") && !peer.contains_key("publickey") {
        return Err(DecryptionError::plain(
            "فایل معتبر کانفیگ WireGuard نیست (کلید خصوصی یا عمومی یافت نشد).",
        ));
    }

    let mut server = "127.0.0.1".to_string();
    let mut port = 51820u16;
    if let Some(ep) = peer.get("endpoint") {
        if let Some(last_colon) = ep.rfind(':') {
            let host_part = &ep[..last_colon];
            server = host_part
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host_part)
                .to_string();
            port = ep[last_colon + 1..].parse::<u16>().unwrap_or(51820);
        } else {
            server = ep.clone();
        }
    }

    let name = if !custom_name.is_empty() {
        custom_name
    } else {
        let stripped = file_name.trim_end_matches(".conf").trim_end_matches(".CONF");
        if stripped.is_empty() {
            "WireGuard".to_string()
        } else {
            stripped.to_string()
        }
    };

    let mut awg = AmneziaWgOptions::default();
    let mut has_awg = false;
    let parse_i64 = |k: &str| iface.get(k).and_then(|v| v.parse::<i64>().ok());
    if let Some(v) = parse_i64("jc") { awg.jc = Some(v); has_awg = true; }
    if let Some(v) = parse_i64("jmin") { awg.jmin = Some(v); has_awg = true; }
    if let Some(v) = parse_i64("jmax") { awg.jmax = Some(v); has_awg = true; }
    if let Some(v) = parse_i64("s1") { awg.s1 = Some(v); has_awg = true; }
    if let Some(v) = parse_i64("s2") { awg.s2 = Some(v); has_awg = true; }
    if let Some(v) = parse_i64("h1") { awg.h1 = Some(v.to_string()); has_awg = true; }
    if let Some(v) = parse_i64("h2") { awg.h2 = Some(v.to_string()); has_awg = true; }
    if let Some(v) = parse_i64("h3") { awg.h3 = Some(v.to_string()); has_awg = true; }
    if let Some(v) = parse_i64("h4") { awg.h4 = Some(v.to_string()); has_awg = true; }
    if let Some(v) = iface.get("i1") { awg.i1 = Some(v.clone()); has_awg = true; }

    let reserved = iface.get("reserved").map(|r| {
        r.split(',')
            .filter_map(|n| n.trim().parse::<i32>().ok())
            .collect::<Vec<_>>()
    }).filter(|v| !v.is_empty());

    let dns = iface
        .get("dns")
        .map(|d| d.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();

    Ok(ProxyProfile {
        name,
        protocol: "wireguard".to_string(),
        server,
        server_port: port,
        private_key: iface.get("privatekey").cloned().unwrap_or_default(),
        public_key: peer.get("publickey").cloned().unwrap_or_default(),
        preshared_key: peer.get("presharedkey").cloned().unwrap_or_default(),
        local_address: iface
            .get("address")
            .cloned()
            .unwrap_or_else(|| "10.0.0.2/32".to_string()),
        mtu: Some(iface.get("mtu").and_then(|v| v.parse().ok()).unwrap_or(1420)),
        dns,
        keepalive: Some(
            peer.get("persistentkeepalive")
                .and_then(|v| v.parse().ok())
                .unwrap_or(25),
        ),
        reserved,
        amnezia_options: if has_awg { Some(awg) } else { None },
        ..Default::default()
    })
}
