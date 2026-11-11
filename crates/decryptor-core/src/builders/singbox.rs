use crate::models::ProxyProfile;
use crate::parsers::subscription::is_dns_protocol;
use crate::sanitizer::{
    clean_proxy_name, filter_and_deduplicate_with_stats, is_valid_curve25519_key,
    remove_control_chars,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const VALID_UTLS_FPS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
];

fn normalize_utls(fp: &str) -> Option<Value> {
    let f = fp.to_lowercase();
    let f = f.trim();
    if VALID_UTLS_FPS.contains(&f) {
        Some(json!({ "enabled": true, "fingerprint": f }))
    } else {
        None
    }
}

fn build_tls_object(p: &ProxyProfile, force_tls: bool) -> Option<Value> {
    let is_reality = p.reality || p.security == "reality";
    let is_tls = force_tls || p.tls || p.security == "tls" || is_reality;
    if !is_tls {
        return None;
    }

    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    let sni = if !p.sni.is_empty() {
        p.sni.as_str()
    } else if !p.host.is_empty() {
        p.host.as_str()
    } else {
        p.server.as_str()
    };
    if !sni.is_empty() {
        tls.insert("server_name".into(), Value::String(sni.into()));
    }
    if p.skip_cert_verify && !is_reality {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    if !p.alpn.is_empty() {
        tls.insert("alpn".into(), json!(p.alpn));
    }
    if is_reality {
        if let Some(utls) = normalize_utls(if p.fingerprint.is_empty() {
            "chrome"
        } else {
            &p.fingerprint
        }) {
            tls.insert("utls".into(), utls);
        }
        if !p.public_key.is_empty() {
            let mut rel = Map::new();
            rel.insert("enabled".into(), Value::Bool(true));
            rel.insert("public_key".into(), Value::String(p.public_key.clone()));
            if !p.short_id.is_empty() {
                rel.insert("short_id".into(), Value::String(p.short_id.clone()));
            }
            tls.insert("reality".into(), Value::Object(rel));
        }
    } else if !p.fingerprint.is_empty() {
        if let Some(utls) = normalize_utls(&p.fingerprint) {
            tls.insert("utls".into(), utls);
        }
    }
    Some(Value::Object(tls))
}

fn build_transport_object(p: &ProxyProfile) -> Option<Value> {
    let net = p.network.to_lowercase();
    let net = net.trim();
    match net {
        "" | "tcp" | "udp" | "kcp" | "raw" => None,
        "ws" => {
            let mut tr = Map::new();
            tr.insert("type".into(), Value::String("ws".into()));
            tr.insert(
                "path".into(),
                Value::String(if p.path.is_empty() { "/".into() } else { p.path.clone() }),
            );
            let h = if !p.host.is_empty() {
                p.host.as_str()
            } else {
                p.sni.as_str()
            };
            if !h.is_empty() {
                tr.insert("headers".into(), json!({ "Host": h }));
            }
            Some(Value::Object(tr))
        }
        "httpupgrade" => {
            let mut tr = Map::new();
            tr.insert("type".into(), Value::String("httpupgrade".into()));
            tr.insert(
                "path".into(),
                Value::String(if p.path.is_empty() { "/".into() } else { p.path.clone() }),
            );
            let h = if !p.host.is_empty() {
                p.host.as_str()
            } else {
                p.sni.as_str()
            };
            if !h.is_empty() {
                tr.insert("host".into(), Value::String(h.into()));
            }
            Some(Value::Object(tr))
        }
        "grpc" => {
            let mut tr = Map::new();
            tr.insert("type".into(), Value::String("grpc".into()));
            let svc = if !p.service_name.is_empty() {
                p.service_name.as_str()
            } else {
                p.path.as_str()
            };
            if !svc.is_empty() {
                tr.insert("service_name".into(), Value::String(svc.into()));
            }
            Some(Value::Object(tr))
        }
        "http" | "h2" | "xhttp" | "splithttp" => {
            let mut tr = Map::new();
            tr.insert("type".into(), Value::String("http".into()));
            if !p.path.is_empty() {
                tr.insert("path".into(), Value::String(p.path.clone()));
            }
            let h = if !p.host.is_empty() {
                p.host.as_str()
            } else {
                p.sni.as_str()
            };
            if !h.is_empty() {
                tr.insert("host".into(), json!([h]));
            }
            Some(Value::Object(tr))
        }
        _ => None,
    }
}

pub fn build_singbox_outbound(p: &ProxyProfile, index: usize) -> Option<(Value, bool)> {
    if p.is_dns_tunnel || is_dns_protocol(&p.protocol) {
        return None;
    }
    let proto = p.protocol.to_lowercase();
    let proto = proto.trim();
    if p.server.trim().is_empty() {
        return None;
    }
    let port = if p.server_port == 0 { 443 } else { p.server_port };
    let tag = clean_proxy_name(&p.name, &format!("Proxy-{}", index + 1));

    match proto {
        "vless" => {
            if p.uuid.trim().is_empty() {
                return None;
            }
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("vless".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("uuid".into(), Value::String(p.uuid.trim().into()));
            if !p.flow.is_empty() {
                ob.insert("flow".into(), Value::String(p.flow.clone()));
            }
            if let Some(tls) = build_tls_object(p, false) {
                ob.insert("tls".into(), tls);
            }
            if let Some(tr) = build_transport_object(p) {
                ob.insert("transport".into(), tr);
            }
            Some((Value::Object(ob), false))
        }
        "vmess" => {
            if p.uuid.trim().is_empty() {
                return None;
            }
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("vmess".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("uuid".into(), Value::String(p.uuid.trim().into()));
            ob.insert(
                "security".into(),
                Value::String(if p.cipher.is_empty() {
                    "auto".into()
                } else {
                    p.cipher.clone()
                }),
            );
            ob.insert("alter_id".into(), json!(p.alter_id.unwrap_or(0)));
            if let Some(tls) = build_tls_object(p, false) {
                ob.insert("tls".into(), tls);
            }
            if let Some(tr) = build_transport_object(p) {
                ob.insert("transport".into(), tr);
            }
            Some((Value::Object(ob), false))
        }
        "trojan" => {
            let pass = if !p.password.is_empty() {
                p.password.trim()
            } else {
                p.uuid.trim()
            };
            if pass.is_empty() {
                return None;
            }
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("trojan".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("password".into(), Value::String(pass.into()));
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            if let Some(tr) = build_transport_object(p) {
                ob.insert("transport".into(), tr);
            }
            Some((Value::Object(ob), false))
        }
        "shadowsocks" | "ss" => {
            if p.password.is_empty() {
                return None;
            }
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("shadowsocks".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert(
                "method".into(),
                Value::String(if !p.cipher.is_empty() {
                    p.cipher.clone()
                } else if !p.method.is_empty() {
                    p.method.clone()
                } else {
                    "aes-256-gcm".into()
                }),
            );
            ob.insert("password".into(), Value::String(p.password.clone()));
            Some((Value::Object(ob), false))
        }
        "socks5" | "socks" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("socks".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("version".into(), Value::String("5".into()));
            if !p.username.is_empty() {
                ob.insert("username".into(), Value::String(p.username.clone()));
            }
            if !p.password.is_empty() {
                ob.insert("password".into(), Value::String(p.password.clone()));
            }
            Some((Value::Object(ob), false))
        }
        "http" | "https" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("http".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            if !p.username.is_empty() {
                ob.insert("username".into(), Value::String(p.username.clone()));
            }
            if !p.password.is_empty() {
                ob.insert("password".into(), Value::String(p.password.clone()));
            }
            if p.tls || proto == "https" {
                if let Some(tls) = build_tls_object(p, true) {
                    ob.insert("tls".into(), tls);
                }
            }
            Some((Value::Object(ob), false))
        }
        "hysteria2" | "hy2" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("hysteria2".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            if let Some(ref ports) = p.ports {
                if !ports.is_empty() {
                    let s_ports: Vec<String> = ports
                        .split(',')
                        .map(|s| s.trim().replace('-', ":"))
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !s_ports.is_empty() {
                        ob.insert("server_ports".into(), json!(s_ports));
                        ob.remove("server_port");
                    }
                }
            }
            if let Some(hop) = p.hop_interval {
                ob.insert("hop_interval".into(), Value::String(format!("{}s", hop)));
            }
            ob.insert("password".into(), Value::String(p.password.clone()));
            if !p.obfs.is_empty() && !p.obfs_password.is_empty() {
                ob.insert(
                    "obfs".into(),
                    json!({ "type": p.obfs, "password": p.obfs_password }),
                );
            }
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            Some((Value::Object(ob), false))
        }
        "hysteria" | "hy" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("hysteria".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            let auth = if !p.auth_str.is_empty() {
                p.auth_str.clone()
            } else {
                p.password.clone()
            };
            if !auth.is_empty() {
                ob.insert("auth_str".into(), Value::String(auth));
            }
            ob.insert(
                "up_mbps".into(),
                json!(p
                    .up
                    .as_deref()
                    .and_then(|s| s.split_whitespace().next())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(50)),
            );
            ob.insert(
                "down_mbps".into(),
                json!(p
                    .down
                    .as_deref()
                    .and_then(|s| s.split_whitespace().next())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(50)),
            );
            if !p.obfs.is_empty() {
                ob.insert("obfs".into(), Value::String(p.obfs.clone()));
            }
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            Some((Value::Object(ob), false))
        }
        "tuic" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("tuic".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("uuid".into(), Value::String(p.uuid.clone()));
            ob.insert("password".into(), Value::String(p.password.clone()));
            ob.insert(
                "congestion_control".into(),
                Value::String(
                    p.congestion_control
                        .clone()
                        .unwrap_or_else(|| "bbr".into()),
                ),
            );
            ob.insert(
                "udp_relay_mode".into(),
                Value::String(
                    p.udp_relay_mode
                        .clone()
                        .unwrap_or_else(|| "native".into()),
                ),
            );
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            Some((Value::Object(ob), false))
        }
        "anytls" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("anytls".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("password".into(), Value::String(p.password.clone()));
            if let Some(ref ici) = p.idle_session_check_interval {
                ob.insert("idle_session_check_interval".into(), Value::String(ici.clone()));
            }
            if let Some(ref ist) = p.idle_session_timeout {
                ob.insert("idle_session_timeout".into(), Value::String(ist.clone()));
            }
            if let Some(mis) = p.min_idle_session {
                ob.insert("min_idle_session".into(), json!(mis));
            }
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            Some((Value::Object(ob), false))
        }
        "naive" | "naive+https" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("naive".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert("server_port".into(), json!(port));
            ob.insert("username".into(), Value::String(p.username.clone()));
            ob.insert("password".into(), Value::String(p.password.clone()));
            if let Some(tls) = build_tls_object(p, true) {
                ob.insert("tls".into(), tls);
            }
            Some((Value::Object(ob), false))
        }
        "ssh" => {
            let mut ob = Map::new();
            ob.insert("type".into(), Value::String("ssh".into()));
            ob.insert("tag".into(), Value::String(tag));
            ob.insert("server".into(), Value::String(p.server.trim().into()));
            ob.insert(
                "server_port".into(),
                json!(if p.server_port == 0 { 22 } else { p.server_port }),
            );
            ob.insert(
                "user".into(),
                Value::String(if p.username.is_empty() {
                    "root".into()
                } else {
                    p.username.clone()
                }),
            );
            if !p.password.is_empty() {
                ob.insert("password".into(), Value::String(p.password.clone()));
            }
            if let Some(ref pk) = p.ssh_private_key {
                if !pk.is_empty() {
                    ob.insert("private_key".into(), Value::String(pk.clone()));
                }
            }
            if let Some(ref passph) = p.ssh_private_key_passphrase {
                if !passph.is_empty() {
                    ob.insert("private_key_passphrase".into(), Value::String(passph.clone()));
                }
            }
            Some((Value::Object(ob), false))
        }
        "wireguard" | "wg" => {
            if !is_valid_curve25519_key(&p.private_key)
                || !is_valid_curve25519_key(&p.peer_public_key)
            {
                return None;
            }
            let ip_re = Regex::new(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$").unwrap();
            let raw_addrs: Vec<&str> = p
                .local_address
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            let mut addresses = Vec::new();
            for a in raw_addrs {
                if ip_re.is_match(a) {
                    if a.contains('/') {
                        addresses.push(a.to_string());
                    } else {
                        addresses.push(format!("{}/32", a));
                    }
                } else if a.contains(':') {
                    if a.contains('/') {
                        addresses.push(a.to_string());
                    } else {
                        addresses.push(format!("{}/128", a));
                    }
                }
            }
            if addresses.is_empty() {
                addresses.push("10.0.0.2/32".to_string());
            }
            if let Some(ref v6) = p.ipv6 {
                let s = v6.trim();
                if !s.is_empty() {
                    addresses.push(if s.contains('/') {
                        s.to_string()
                    } else {
                        format!("{}/128", s)
                    });
                }
            }
            let mut peer = Map::new();
            peer.insert("address".into(), Value::String(p.server.trim().into()));
            peer.insert(
                "port".into(),
                json!(if p.server_port == 0 { 51820 } else { p.server_port }),
            );
            peer.insert("public_key".into(), Value::String(p.peer_public_key.trim().into()));
            if is_valid_curve25519_key(&p.preshared_key) {
                peer.insert(
                    "pre_shared_key".into(),
                    Value::String(p.preshared_key.trim().into()),
                );
            }
            peer.insert("allowed_ips".into(), json!(["0.0.0.0/0", "::/0"]));
            if let Some(ref res) = p.reserved {
                if res.len() == 3 {
                    peer.insert("reserved".into(), json!(res));
                }
            }

            let ep = json!({
                "type": "wireguard",
                "tag": tag,
                "address": addresses,
                "private_key": p.private_key.trim(),
                "peers": [Value::Object(peer)],
                "mtu": p.mtu.unwrap_or(1408),
                "udp_timeout": "5m"
            });
            Some((ep, true))
        }
        _ => None,
    }
}

pub fn build_singbox_config(
    raw_profiles: &[ProxyProfile],
    filter_duplicates: bool,
    filter_broken: bool,
    skip_filter: bool,
) -> String {
    let profiles = if skip_filter {
        raw_profiles.to_vec()
    } else {
        filter_and_deduplicate_with_stats(raw_profiles, filter_duplicates, filter_broken).0
    };

    let selector_tag = "انتخاب دستی 🤏🏻";
    let auto_tag = "خودکار (بهترین پینگ) 🤖";

    let mut used_tags: HashSet<String> = [
        "direct",
        "block",
        selector_tag,
        auto_tag,
        "تلگرام 💬",
        "یوتیوب ▶️",
        "گوگل 🌍",
        "هوش مصنوعی 🤖",
        "mixed-in",
        "tun-in",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();

    let mut endpoints = Vec::new();
    let mut outbounds = Vec::new();
    let mut proxy_tags = Vec::new();

    for (i, p) in profiles.iter().enumerate() {
        if let Some((mut ob, is_ep)) = build_singbox_outbound(p, i) {
            let base_tag = ob
                .get("tag")
                .and_then(|v| v.as_str())
                .map(remove_control_chars)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("Proxy-{}", i + 1));
            let mut unique_tag = base_tag.clone();
            let mut cnt = 1usize;
            while !used_tags.insert(unique_tag.clone()) {
                unique_tag = format!("{} #{}", base_tag, cnt);
                cnt += 1;
            }
            if let Some(obj) = ob.as_object_mut() {
                obj.insert("tag".into(), Value::String(unique_tag.clone()));
            }
            if is_ep {
                endpoints.push(ob);
            } else {
                outbounds.push(ob);
            }
            proxy_tags.push(unique_tag);
        }
    }

    if proxy_tags.is_empty() {
        proxy_tags.push("direct".to_string());
    }

    let mut sel_list = vec![auto_tag.to_string()];
    sel_list.extend(proxy_tags.iter().cloned());
    sel_list.push("direct".to_string());

    let mut cat_list = vec![selector_tag.to_string(), auto_tag.to_string()];
    cat_list.extend(proxy_tags.iter().cloned());

    let mut all_outbounds = vec![
        json!({
            "type": "selector",
            "tag": selector_tag,
            "outbounds": sel_list
        }),
        json!({
            "type": "urltest",
            "tag": auto_tag,
            "outbounds": proxy_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50
        }),
        json!({ "type": "selector", "tag": "تلگرام 💬", "outbounds": cat_list }),
        json!({ "type": "selector", "tag": "یوتیوب ▶️", "outbounds": cat_list }),
        json!({ "type": "selector", "tag": "گوگل 🌍", "outbounds": cat_list }),
        json!({ "type": "selector", "tag": "هوش مصنوعی 🤖", "outbounds": cat_list }),
    ];
    all_outbounds.extend(outbounds);
    all_outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    all_outbounds.push(json!({ "type": "block", "tag": "block" }));

    let mut root = Map::new();
    root.insert(
        "log".into(),
        json!({
            "disabled": false,
            "level": "warn",
            "timestamp": true
        }),
    );
    if !endpoints.is_empty() {
        root.insert("endpoints".into(), Value::Array(endpoints));
    }
    root.insert(
        "dns".into(),
        json!({
            "servers": [
                {
                    "tag": "dns-remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "detour": selector_tag
                },
                {
                    "tag": "dns-direct",
                    "type": "https",
                    "server": "178.22.122.100",
                    "detour": "direct"
                },
                {
                    "tag": "dns-local",
                    "type": "local",
                    "detour": "direct"
                }
            ],
            "rules": [
                {
                    "rule_set": [
                        "geosite-category-ads-all",
                        "geosite-malware",
                        "geosite-phishing",
                        "geosite-cryptominers"
                    ],
                    "action": "predefined",
                    "rcode": "REFUSED"
                },
                {
                    "domain_suffix": [".ir"],
                    "rule_set": [
                        "geosite-ir",
                        "geosite-arvancloud",
                        "geosite-derakcloud",
                        "geosite-iranserver",
                        "geosite-parspack"
                    ],
                    "server": "dns-direct"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4"
        }),
    );
    root.insert(
        "inbounds".into(),
        json!([
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            },
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": ["172.19.0.1/30"],
                "auto_route": true,
                "strict_route": true,
                "stack": "mixed"
            }
        ]),
    );
    root.insert("outbounds".into(), Value::Array(all_outbounds));
    root.insert(
        "route".into(),
        json!({
            "rule_set": [
                {
                    "tag": "geosite-ir",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-ir.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geoip-ir",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geoip-ir.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-category-ads-all",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-malware",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-malware.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-phishing",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-phishing.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-cryptominers",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-cryptominers.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-arvancloud",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-arvancloud.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-derakcloud",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-derakcloud.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-iranserver",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-iranserver.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-parspack",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/main/rule-set/geosite-parspack.srs",
                    "download_detour": "direct"
                }
            ],
            "rules": [
                { "action": "sniff" },
                { "protocol": "dns", "action": "hijack-dns" },
                {
                    "rule_set": [
                        "geosite-category-ads-all",
                        "geosite-malware",
                        "geosite-phishing",
                        "geosite-cryptominers"
                    ],
                    "outbound": "block"
                },
                {
                    "domain_suffix": [".ir"],
                    "rule_set": [
                        "geosite-ir",
                        "geoip-ir",
                        "geosite-arvancloud",
                        "geosite-derakcloud",
                        "geosite-iranserver",
                        "geosite-parspack"
                    ],
                    "outbound": "direct"
                },
                {
                    "ip_is_private": true,
                    "outbound": "direct"
                }
            ],
            "final": selector_tag,
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-remote"
        }),
    );
    root.insert(
        "ntp".into(),
        json!({
            "enabled": true,
            "server": "time.cloudflare.com",
            "server_port": 123,
            "domain_resolver": "dns-direct",
            "interval": "30m"
        }),
    );
    root.insert(
        "experimental".into(),
        json!({
            "cache_file": {
                "enabled": true,
                "store_fakeip": true
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "Rule"
            }
        }),
    );

    serde_json::to_string_pretty(&Value::Object(root)).unwrap_or_else(|_| "{}".into())
}
