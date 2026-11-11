use crate::crypto_utils::{base64_decode_safe, base64_url_decode, inflate_zlib};
use crate::http_client::fetch_text_with_fallback;
use crate::models::{AmneziaWgOptions, DecryptionError, ProxyMode, ProxyProfile};
use crate::parsers::mihomo::{clash_object_to_profile, parse_mihomo_yaml_async};
use crate::parsers::singbox::parse_singbox_json;
use crate::sanitizer::{clean_proxy_name, remove_control_chars, unpack_v2ray_json_profile};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

pub const DNS_PROTOCOLS: &[&str] = &[
    "dns", "nm-dns", "nm-vless", "slipnet-enc", "slipnet", "slipstream", "dnstt", "dnst",
    "dnstunnel", "vaydns", "stormdns", "cottendns", "masterdns", "masterdnsvpn", "noizdns",
    "slowdns", "ssh-dns", "dns-ssh", "ssh-over-dns", "whitedns",
];

pub fn is_dns_protocol(proto_or_link: &str) -> bool {
    let s = proto_or_link.to_lowercase();
    let trimmed = s.trim();
    DNS_PROTOCOLS.iter().any(|&dp| {
        trimmed == dp
            || trimmed.starts_with(&format!("{}://", dp))
            || trimmed.starts_with(&format!("{}%3a", dp))
    })
}

pub fn normalize_subscription_url(raw_url: &str) -> String {
    let mut clean = raw_url
        .trim()
        .trim_end_matches(|c| matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}'))
        .to_string();
    if let Some((before_pipe, _)) = clean.split_once('|') {
        clean = before_pipe.trim().to_string();
    }
    static GH_RE: OnceLock<Regex> = OnceLock::new();
    let gh_re = GH_RE.get_or_init(|| {
        Regex::new(r"(?i)^https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw)(?:/refs/heads)?/([^/]+)/(.+)$").unwrap()
    });
    if let Some(cap) = gh_re.captures(&clean) {
        let file_path = cap[4].replace("%2F", "/").replace("%2f", "/");
        clean = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            &cap[1], &cap[2], &cap[3], file_path
        );
    }
    if clean.contains("raw.githubusercontent.com") {
        clean = clean.replace("%2F", "/").replace("%2f", "/");
    }
    clean
}

fn percent_decode_plus(s: &str, plus_as_space: bool) -> String {
    let input = if plus_as_space {
        s.replace('+', " ")
    } else {
        s.to_string()
    };
    percent_decode_bytes(&input)
}

fn percent_decode_bytes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn split_concatenated_links(text: &str) -> Vec<String> {
    static BOUNDARY_RE: OnceLock<Regex> = OnceLock::new();
    static REPLACE_RE: OnceLock<Regex> = OnceLock::new();
    static TG_RE: OnceLock<Regex> = OnceLock::new();

    let mut schemes = vec![
        "vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "hy2", "hysteria", "wireguard", "wg",
        "masque", "tuic", "snell", "shadowtls", "anytls", "ssh", "socks5", "socks", "vpn", "naive",
        "naive+https", "tailcat", "dns", "nm-dns", "nm-vless", "slipnet-enc", "slipnet",
        "slipstream", "dnstt", "dnst", "dnstunnel", "vaydns", "stormdns", "cottendns", "masterdns",
        "masterdnsvpn", "noizdns", "slowdns", "ssh-dns", "dns-ssh", "ssh-over-dns", "whitedns",
    ];
    schemes.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let escaped: Vec<String> = schemes.into_iter().map(|s| regex::escape(s)).collect();
    let pattern = escaped.join("|");

    let boundary_re = BOUNDARY_RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)(?:(?:{})(?://|://|%3[aA]//|%3[aA]%2[fF]%2[fF]|://)|(?:{})(?:://|%3[aA]//|%3[aA]%2[fF]%2[fF])|https?://)",
            pattern, pattern
        )).unwrap()
    });
    // Exact scheme boundary matching (avoid partial redundancy):
    static EXACT_BOUNDARY_RE: OnceLock<Regex> = OnceLock::new();
    let _ = boundary_re;
    let exact_re = EXACT_BOUNDARY_RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)(?:(?:{})(?:://|%3[aA]//|%3[aA]%2[fF]%2[fF])|https?://)",
            pattern
        ))
        .unwrap()
    });

    let replace_re = REPLACE_RE.get_or_init(|| {
        Regex::new(&format!(r"(?i)^({})(?:%3a//|%3a%2f%2f)", pattern)).unwrap()
    });
    let tg_re = TG_RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:https?://t\.me/(?:socks|proxy)\?|tg://(?:socks|proxy)\?)").unwrap()
    });

    let mut raw_links = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if tg_re.is_match(trimmed) {
            raw_links.push(trimmed.to_string());
            continue;
        }

        let matches: Vec<(usize, &str)> = exact_re
            .find_iter(trimmed)
            .filter_map(|m| {
                if m.start() == 0 {
                    return Some((m.start(), m.as_str()));
                }
                let low = m.as_str().to_lowercase();
                if low.starts_with("http://") || low.starts_with("https://") {
                    if let Some(prev) = trimmed[..m.start()].chars().next_back() {
                        if matches!(prev, '@' | '=' | '&' | ':' | '%' | '?') {
                            return None;
                        }
                    }
                }
                Some((m.start(), m.as_str()))
            })
            .collect();

        if matches.is_empty() {
            continue;
        }

        let trim_tail = |s: &str| -> String {
            s.trim_end_matches(|c: char| {
                matches!(
                    c,
                    '.' | ',' | ';' | '(' | ')' | '[' | ']' | '"' | '\'' | '<' | '>' | '`' | ' ' | '\t' | '\r'
                )
            })
            .trim()
            .to_string()
        };

        if matches.len() == 1 && matches[0].0 == 0 {
            let mut clean = trim_tail(trimmed);
            clean = replace_re.replace(&clean, "$1://").into_owned();
            if !clean.is_empty() {
                raw_links.push(clean);
            }
            continue;
        }

        for i in 0..matches.len() {
            let start = matches[i].0;
            let end = if i + 1 < matches.len() {
                matches[i + 1].0
            } else {
                trimmed.len()
            };
            let mut chunk = trim_tail(&trimmed[start..end]);
            chunk = replace_re.replace(&chunk, "$1://").into_owned();
            if !chunk.is_empty() {
                raw_links.push(chunk);
            }
        }
    }
    raw_links
}

fn normalize_ipv6_uri_brackets(uri: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^([a-zA-Z0-9+_-]+://[^@]+@)([0-9a-fA-F:]+):(\d+)(.*)$").unwrap()
    });
    if let Some(cap) = re.captures(uri) {
        let host = &cap[2];
        if host.contains(':') && !host.starts_with('[') {
            return format!("{}[{}]:{}{}", &cap[1], host, &cap[3], &cap[4]);
        }
    }
    uri.to_string()
}

fn query_map(u: &Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn parse_anytls_uri(uri: &str) -> Option<ProxyProfile> {
    if !uri.to_lowercase().starts_with("anytls://") {
        return None;
    }
    let body = uri[9..].trim();
    let (without_hash, hash) = match body.split_once('#') {
        Some((b, h)) => (b, percent_decode_plus(h, false)),
        None => (body, String::new()),
    };
    let (auth_and_host, query_str) = match without_hash.split_once('?') {
        Some((ah, q)) => (ah, q),
        None => (without_hash, ""),
    };

    let mut q_map: HashMap<String, String> = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
        q_map.insert(k.into_owned(), v.into_owned());
    }

    let at_idx = auth_and_host.rfind('@')?;
    let password = percent_decode_plus(&auth_and_host[..at_idx], false);
    let mut host_port = auth_and_host[at_idx + 1..].trim();
    if let Some((hp, _)) = host_port.split_once('/') {
        host_port = hp;
    }

    let (server, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        let srv = rest[..end].to_string();
        let rem = &rest[end + 1..];
        let pt = if let Some(p_str) = rem.strip_prefix(':') {
            p_str.parse::<u16>().unwrap_or(443)
        } else {
            443
        };
        (srv, pt)
    } else if let Some((h, p_str)) = host_port.rsplit_once(':') {
        (h.to_string(), p_str.parse::<u16>().unwrap_or(443))
    } else {
        (host_port.to_string(), 443)
    };

    if server.is_empty() || password.is_empty() {
        return None;
    }

    let sni = q_map
        .get("sni")
        .or_else(|| q_map.get("peer"))
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| server.clone());
    let insecure = matches!(
        q_map.get("insecure").or_else(|| q_map.get("allowInsecure")).map(|s| s.as_str()),
        Some("1" | "true")
    );
    let fp = q_map
        .get("fp")
        .or_else(|| q_map.get("fingerprint"))
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "chrome".to_string());
    let alpn = q_map
        .get("alpn")
        .map(|a| {
            a.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let udp = q_map.get("udp").map(|v| v != "0").unwrap_or(true);

    Some(ProxyProfile {
        name: clean_proxy_name(&hash, "AnyTLS"),
        protocol: "anytls".to_string(),
        server,
        server_port: port,
        password,
        sni,
        tls: true,
        security: "tls".to_string(),
        skip_cert_verify: insecure,
        fingerprint: fp,
        alpn,
        udp: Some(udp),
        idle_session_check_interval: Some(
            q_map
                .get("idle_session_check_interval")
                .or_else(|| q_map.get("idle-session-check-interval"))
                .cloned()
                .unwrap_or_else(|| "30s".to_string()),
        ),
        idle_session_timeout: Some(
            q_map
                .get("idle_session_timeout")
                .or_else(|| q_map.get("idle-session-timeout"))
                .cloned()
                .unwrap_or_else(|| "30s".to_string()),
        ),
        min_idle_session: Some(
            q_map
                .get("min_idle_session")
                .or_else(|| q_map.get("min-idle-session"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        ),
        client_metadata: q_map
            .get("client_metadata")
            .or_else(|| q_map.get("client-metadata"))
            .cloned()
            .filter(|s| !s.is_empty()),
        raw_uri: Some(uri.to_string()),
        ..Default::default()
    })
}

pub fn parse_naive_uri(uri: &str) -> Option<ProxyProfile> {
    let raw_hash = uri
        .split_once('#')
        .map(|(_, h)| percent_decode_plus(h, false))
        .unwrap_or_default();
    let without_hash = uri.split('#').next().unwrap_or(uri);
    let normalized = if let Some(rest) = without_hash.strip_prefix("naive+https://") {
        format!("https://{}", rest)
    } else if let Some(rest) = without_hash.strip_prefix("naive://") {
        format!("https://{}", rest)
    } else {
        return None;
    };
    let u = Url::parse(&normalized).ok()?;
    let q = query_map(&u);
    let host = u.host_str()?.to_string();
    let port = u.port().unwrap_or(443);
    let insecure = matches!(
        q.get("insecure").or_else(|| q.get("allowInsecure")).map(|s| s.as_str()),
        Some("1" | "true")
    );
    let quic = matches!(q.get("quic").map(|s| s.as_str()), Some("1" | "true"));
    Some(ProxyProfile {
        name: clean_proxy_name(&raw_hash, "Naive"),
        protocol: "naive".to_string(),
        server: host.clone(),
        server_port: port,
        username: percent_decode_plus(u.username(), false),
        password: percent_decode_plus(u.password().unwrap_or(""), false),
        sni: q.get("sni").cloned().filter(|s| !s.is_empty()).unwrap_or(host),
        tls: true,
        security: "tls".to_string(),
        skip_cert_verify: insecure,
        quic,
        raw_uri: Some(uri.to_string()),
        ..Default::default()
    })
}

pub fn parse_amnezia_vpn_uri(uri: &str) -> Vec<ProxyProfile> {
    let raw = uri
        .trim()
        .strip_prefix("vpn://")
        .or_else(|| uri.trim().strip_prefix("VPN://"))
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let Ok(buf) = base64_url_decode(raw) else {
        return Vec::new();
    };
    if buf.len() < 8 {
        return Vec::new();
    }
    let dec = inflate_zlib(&buf[4..]).or_else(|_| inflate_zlib(&buf));
    let Ok(bytes) = dec else {
        return Vec::new();
    };
    let Ok(data) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };

    let host_name = data
        .get("hostName")
        .or_else(|| data.get("ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .to_string();
    let desc = data
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Amnezia")
        .to_string();
    let dns1 = data.get("dns1").and_then(|v| v.as_str()).unwrap_or("1.1.1.1").to_string();
    let dns2 = data.get("dns2").and_then(|v| v.as_str()).unwrap_or("1.0.0.1").to_string();

    let mut results = Vec::new();
    let Some(containers) = data.get("containers").and_then(|v| v.as_array()) else {
        return results;
    };

    for c in containers {
        let c_type = c
            .get("container")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if c_type.contains("awg") || c_type.contains("wireguard") || c.get("awg").is_some() || c.get("wireguard").is_some() {
            if let Some(awg) = c.get("awg").or_else(|| c.get("wireguard")) {
                let last_conf_raw = awg
                    .get("last_config")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let last_conf: Value = serde_json::from_str(last_conf_raw).unwrap_or(Value::Null);
                let get_s = |k: &str| {
                    last_conf
                        .get(k)
                        .or_else(|| awg.get(k))
                        .and_then(|v| match v {
                            Value::String(st) => Some(st.clone()),
                            Value::Number(n) => Some(n.to_string()),
                            _ => None,
                        })
                };
                let ini_candidate = last_conf
                    .get("config")
                    .or_else(|| awg.get("config"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        if last_conf_raw.contains("[Interface]") {
                            Some(last_conf_raw)
                        } else {
                            None
                        }
                    });
                let mut pushed_from_ini = false;
                if let Some(ini_txt) = ini_candidate {
                    if let Ok(mut wg) = crate::parsers::wireguard::parse_wireguard_conf(ini_txt, &desc) {
                        wg.name = clean_proxy_name(&format!("{} (AWG)", desc), "AmneziaWG");
                        if (wg.server == "127.0.0.1" || wg.server.is_empty()) && host_name != "127.0.0.1" {
                            wg.server = get_s("hostName").unwrap_or_else(|| host_name.clone());
                        }
                        if wg.dns.is_empty() {
                            wg.dns = vec![dns1.clone(), dns2.clone()];
                        }
                        results.push(wg);
                        pushed_from_ini = true;
                    }
                }
                if !pushed_from_ini {
                    let srv = get_s("hostName").unwrap_or_else(|| host_name.clone());
                    let port = get_s("port").and_then(|s| s.parse::<u16>().ok()).unwrap_or(51820);
                    let priv_key = get_s("client_priv_key").unwrap_or_default();
                    let peer_pub = get_s("server_pub_key").unwrap_or_default();
                    let psk = get_s("psk_key").unwrap_or_default();
                    let client_ip = get_s("client_ip")
                        .unwrap_or_else(|| "10.8.1.2".to_string())
                        .split('/')
                        .next()
                        .unwrap_or("10.8.1.2")
                        .to_string();
                    let mtu = get_s("mtu").and_then(|s| s.parse::<u32>().ok()).unwrap_or(1420);

                    let has_awg = get_s("Jc").is_some() || get_s("H1").is_some();
                    let amnezia_options = if has_awg {
                        Some(AmneziaWgOptions {
                            jc: get_s("Jc").and_then(|s| s.parse().ok()),
                            jmin: get_s("Jmin").and_then(|s| s.parse().ok()),
                            jmax: get_s("Jmax").and_then(|s| s.parse().ok()),
                            s1: get_s("S1").and_then(|s| s.parse().ok()),
                            s2: get_s("S2").and_then(|s| s.parse().ok()),
                            h1: get_s("H1"),
                            h2: get_s("H2"),
                            h3: get_s("H3"),
                            h4: get_s("H4"),
                            ..Default::default()
                        })
                    } else {
                        None
                    };

                    results.push(ProxyProfile {
                        name: clean_proxy_name(&format!("{} (AWG)", desc), "AmneziaWG"),
                        protocol: "wireguard".to_string(),
                        server: srv,
                        server_port: port,
                        private_key: priv_key,
                        peer_public_key: peer_pub.clone(),
                        public_key: peer_pub,
                        preshared_key: psk,
                        local_address: client_ip,
                        dns: vec![dns1.clone(), dns2.clone()],
                        mtu: Some(mtu),
                        amnezia_options,
                        ..Default::default()
                    });
                }
            }
        }

        if c_type.contains("openvpn") || c.get("openvpn").is_some() {
            if let Some(ovpn) = c.get("openvpn") {
                let config_str = ovpn
                    .get("config")
                    .or_else(|| ovpn.get("last_config"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let port = ovpn
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1194) as u16;
                results.push(ProxyProfile {
                    name: clean_proxy_name(&format!("{} (OpenVPN)", desc), "Amnezia-OpenVPN"),
                    protocol: "openvpn".to_string(),
                    server: host_name.clone(),
                    server_port: port,
                    ovpn_config: Some(config_str),
                    ..Default::default()
                });
            }
        }

        if c_type.contains("shadowsocks") || c_type.contains("cloak") || c.get("shadowsocks").is_some() {
            if let Some(ss) = c.get("shadowsocks") {
                let last_conf: Value = ss
                    .get("last_config")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null);
                let port = last_conf
                    .get("port")
                    .or_else(|| ss.get("port"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(8388) as u16;
                let cipher = last_conf
                    .get("cipher")
                    .or_else(|| ss.get("cipher"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("chacha20-ietf-poly1305")
                    .to_string();
                let password = last_conf
                    .get("password")
                    .or_else(|| ss.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                results.push(ProxyProfile {
                    name: clean_proxy_name(&format!("{} (SS)", desc), "Amnezia-SS"),
                    protocol: "shadowsocks".to_string(),
                    server: host_name.clone(),
                    server_port: port,
                    method: cipher.clone(),
                    cipher,
                    password,
                    ..Default::default()
                });
            }
        }

        if c_type.contains("xray") || c.get("xray").is_some() {
            if let Some(xray) = c.get("xray") {
                let last_conf: Value = xray
                    .get("last_config")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null);
                let port = last_conf
                    .get("port")
                    .or_else(|| xray.get("port"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(443) as u16;
                let uuid = last_conf
                    .get("uuid")
                    .or_else(|| xray.get("uuid"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                results.push(ProxyProfile {
                    name: clean_proxy_name(&format!("{} (Xray)", desc), "Amnezia-Xray"),
                    protocol: "vless".to_string(),
                    server: host_name.clone(),
                    server_port: port,
                    uuid,
                    ..Default::default()
                });
            }
        }
    }
    results
}

pub fn parse_uri_config(uri_in: &str) -> Option<ProxyProfile> {
    let cleaned = remove_control_chars(uri_in).trim().to_string();
    if cleaned.is_empty() {
        return None;
    }
    let uri = normalize_ipv6_uri_brackets(&cleaned);
    let low = uri.to_lowercase();

    // 1. Telegram SOCKS / Proxy
    if low.starts_with("https://t.me/socks")
        || low.starts_with("https://t.me/proxy")
        || low.starts_with("tg://socks")
        || low.starts_with("tg://proxy")
    {
        let conv = if low.starts_with("tg://") {
            format!("https://t.me/{}", &uri[5..])
        } else {
            uri.clone()
        };
        let u = Url::parse(&conv).ok()?;
        let q = query_map(&u);
        let server = q.get("server")?.clone();
        let port = q.get("port")?.parse::<u16>().ok()?;
        return Some(ProxyProfile {
            name: format!("TG-Proxy-{}:{}", server, port),
            protocol: "socks5".to_string(),
            server,
            server_port: port,
            username: q.get("user").cloned().unwrap_or_default(),
            password: q.get("pass").cloned().unwrap_or_default(),
            ..Default::default()
        });
    }

    // 2. VLESS & Trojan
    if low.starts_with("vless://") || low.starts_with("trojan://") {
        let proto = if low.starts_with("vless://") {
            "vless"
        } else {
            "trojan"
        };
        let u = Url::parse(&uri).ok()?;
        let q = query_map(&u);
        let cred = percent_decode_plus(u.username(), false);
        let server = u
            .host_str()?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = u.port().unwrap_or(443);
        let raw_hash = u
            .fragment()
            .map(|f| percent_decode_plus(f, false))
            .unwrap_or_default();
        let security = q.get("security").cloned().unwrap_or_else(|| "none".to_string());
        let is_tls = security == "tls" || security == "reality";
        let alpn = q
            .get("alpn")
            .map(|a| a.split(',').map(|x| x.trim().to_string()).collect())
            .unwrap_or_default();

        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, proto),
            protocol: proto.to_string(),
            server: server.clone(),
            server_port: port,
            uuid: cred.clone(),
            password: cred,
            flow: q.get("flow").cloned().unwrap_or_default(),
            encryption: q.get("encryption").cloned().unwrap_or_else(|| "none".to_string()),
            network: q.get("type").cloned().unwrap_or_else(|| "tcp".to_string()),
            path: q.get("path").cloned().unwrap_or_default(),
            host: q.get("host").or_else(|| q.get("sni")).cloned().unwrap_or_default(),
            mode: q.get("mode").cloned().unwrap_or_default(),
            service_name: q.get("serviceName").or_else(|| q.get("service")).cloned().unwrap_or_default(),
            security: security.clone(),
            tls: is_tls,
            reality: security == "reality",
            sni: q.get("sni").or_else(|| q.get("peer")).cloned().unwrap_or(server),
            fingerprint: q.get("fp").cloned().unwrap_or_else(|| "chrome".to_string()),
            public_key: q.get("pbk").cloned().unwrap_or_default(),
            short_id: q.get("sid").cloned().unwrap_or_default(),
            spider_x: q.get("spx").cloned().unwrap_or_default(),
            alpn,
            skip_cert_verify: matches!(
                q.get("allowInsecure").or_else(|| q.get("insecure")).map(|s| s.as_str()),
                Some("1" | "true")
            ),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 3. VMess
    if low.starts_with("vmess://") {
        let b64 = uri[8..].trim().split('#').next().unwrap_or("").trim();
        let dec = base64_decode_safe(b64).ok()?;
        let v: Value = serde_json::from_slice(&dec).ok()?;
        let s_f = |k: &str| match v.get(k) {
            Some(Value::String(st)) => st.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };
        let add = s_f("add");
        let id = s_f("id");
        let net = {
            let n = s_f("net");
            if n.is_empty() { "tcp".to_string() } else { n }
        };
        let tls = v.get("tls").and_then(|x| x.as_str()) == Some("tls")
            || v.get("tls").and_then(|x| x.as_bool()) == Some(true);
        let sni = {
            let s = s_f("sni");
            if !s.is_empty() {
                s
            } else {
                let h = s_f("host");
                if !h.is_empty() { h } else { add.clone() }
            }
        };
        let path = s_f("path");
        return Some(ProxyProfile {
            name: clean_proxy_name(&s_f("ps"), "vmess"),
            protocol: "vmess".to_string(),
            server: add,
            server_port: s_f("port").parse::<u16>().unwrap_or(443),
            uuid: id.clone(),
            password: id,
            alter_id: Some(s_f("aid").parse::<u32>().unwrap_or(0)),
            security: {
                let sc = s_f("scy");
                if sc.is_empty() { "auto".to_string() } else { sc }
            },
            network: net,
            path: path.clone(),
            service_name: path,
            host: s_f("host"),
            tls,
            sni,
            fingerprint: {
                let fp = s_f("fp");
                if fp.is_empty() { "chrome".to_string() } else { fp }
            },
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 4. Hysteria 2
    if low.starts_with("hysteria2://") || low.starts_with("hy2://") {
        let rest = uri.split_once("://")?.1;
        let u = Url::parse(&format!("http://{}", rest)).ok()?;
        let q = query_map(&u);
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(443);
        let pw_raw = if !u.username().is_empty() {
            u.username()
        } else {
            u.password().unwrap_or("")
        };
        let password = percent_decode_plus(pw_raw, false);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "hy2"),
            protocol: "hysteria2".to_string(),
            server: server.clone(),
            server_port: port,
            password,
            tls: true,
            sni: q.get("sni").cloned().filter(|s| !s.is_empty()).unwrap_or(server),
            skip_cert_verify: matches!(q.get("insecure").map(|s| s.as_str()), Some("1" | "true")),
            obfs: q.get("obfs").cloned().unwrap_or_default(),
            obfs_password: q.get("obfs-password").cloned().unwrap_or_default(),
            ports: q.get("mport").or_else(|| q.get("ports")).cloned().filter(|s| !s.is_empty()),
            hop_interval: q.get("hop-interval").and_then(|s| s.parse().ok()),
            alpn: q
                .get("alpn")
                .map(|a| a.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["h3".to_string()]),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 5. Hysteria 1
    if low.starts_with("hysteria://") {
        let u = Url::parse(&format!("http://{}", &uri[11..])).ok()?;
        let q = query_map(&u);
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(443);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        let auth = q
            .get("auth")
            .or_else(|| q.get("obfsParam"))
            .cloned()
            .unwrap_or_else(|| percent_decode_plus(u.username(), false));
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "hysteria"),
            protocol: "hysteria".to_string(),
            server: server.clone(),
            server_port: port,
            auth_str: auth.clone(),
            password: auth,
            ssr_protocol: q.get("protocol").cloned().unwrap_or_else(|| "udp".to_string()),
            up: Some(q.get("upmbps").cloned().unwrap_or_else(|| "50 Mbps".to_string())),
            down: Some(q.get("downmbps").cloned().unwrap_or_else(|| "100 Mbps".to_string())),
            sni: q.get("peer").or_else(|| q.get("sni")).cloned().unwrap_or(server),
            tls: true,
            skip_cert_verify: q.get("insecure").map(|s| s == "1").unwrap_or(false),
            alpn: q
                .get("alpn")
                .map(|a| a.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["h3".to_string()]),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 6. TUIC
    if low.starts_with("tuic://") {
        let u = Url::parse(&format!("http://{}", &uri[7..])).ok()?;
        let q = query_map(&u);
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(443);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "tuic"),
            protocol: "tuic".to_string(),
            server: server.clone(),
            server_port: port,
            uuid: percent_decode_plus(u.username(), false),
            password: percent_decode_plus(u.password().unwrap_or(""), false),
            congestion_control: Some(
                q.get("congestion_control")
                    .cloned()
                    .unwrap_or_else(|| "bbr".to_string()),
            ),
            udp_relay_mode: Some(
                q.get("udp_relay_mode")
                    .cloned()
                    .unwrap_or_else(|| "native".to_string()),
            ),
            sni: q.get("sni").cloned().unwrap_or(server),
            tls: true,
            alpn: q
                .get("alpn")
                .map(|a| a.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["h3".to_string()]),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 7. WireGuard / WG
    if low.starts_with("wireguard://") || low.starts_with("wg://") {
        let rest = uri.split_once("://")?.1;
        let u = Url::parse(&format!("http://{}", rest)).ok()?;
        let q = query_map(&u);
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(51820);
        let priv_key = percent_decode_plus(u.username(), false);
        let raw_hash = u
            .fragment()
            .map(|f| percent_decode_plus(f, true))
            .unwrap_or_default();

        let reserved = q.get("reserved").and_then(|r| {
            let clean = r.trim().trim_matches(|c| c == '[' || c == ']');
            let nums: Vec<i32> = clean
                .split(',')
                .filter_map(|x| x.trim().parse::<i32>().ok())
                .collect();
            if nums.is_empty() { None } else { Some(nums) }
        });

        let keepalive = q
            .get("keepalive")
            .or_else(|| q.get("persistent-keepalive"))
            .or_else(|| q.get("persistent_keepalive"))
            .and_then(|v| v.parse::<u32>().ok());

        let mut awg = AmneziaWgOptions::default();
        let mut has_awg = false;
        if let Some(wc) = q.get("wnoisecount").or_else(|| q.get("jc")).and_then(|v| v.parse().ok()) {
            awg.jc = Some(wc);
            has_awg = true;
        }
        if let Some(wp) = q.get("wpayloadsize").or_else(|| q.get("payloadsize")) {
            awg.wpayloadsize = Some(wp.clone());
            if let Some((p1, p2)) = wp.split_once('-') {
                if let (Ok(a), Ok(b)) = (p1.parse::<i64>(), p2.parse::<i64>()) {
                    awg.jmin = Some(a);
                    awg.jmax = Some(b);
                }
            } else if let Ok(a) = wp.parse::<i64>() {
                awg.jmin = Some(a);
                awg.jmax = Some(a);
            }
            has_awg = true;
        }
        for (key_s, slot) in [
            ("jmin", &mut awg.jmin),
            ("jmax", &mut awg.jmax),
            ("s1", &mut awg.s1),
            ("s2", &mut awg.s2),
            ("s3", &mut awg.s3),
            ("s4", &mut awg.s4),
        ] {
            if let Some(val) = q.get(key_s).and_then(|s| s.parse().ok()) {
                *slot = Some(val);
                has_awg = true;
            }
        }
        if let Some(v) = q.get("h1") { awg.h1 = Some(v.clone()); has_awg = true; }
        if let Some(v) = q.get("h2") { awg.h2 = Some(v.clone()); has_awg = true; }
        if let Some(v) = q.get("h3") { awg.h3 = Some(v.clone()); has_awg = true; }
        if let Some(v) = q.get("h4") { awg.h4 = Some(v.clone()); has_awg = true; }
        if let Some(v) = q.get("wnoise") { awg.wnoise = Some(v.clone()); has_awg = true; }
        if let Some(v) = q.get("wnoisedelay") { awg.wnoisedelay = Some(v.clone()); has_awg = true; }

        let psk = q
            .get("presharedkey")
            .or_else(|| q.get("presharedKey"))
            .or_else(|| q.get("preshared-key"))
            .or_else(|| q.get("psk"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        let pub_k = q
            .get("publickey")
            .or_else(|| q.get("publicKey"))
            .or_else(|| q.get("public-key"))
            .or_else(|| q.get("pubkey"))
            .cloned()
            .unwrap_or_default();

        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "wireguard"),
            protocol: "wireguard".to_string(),
            server,
            server_port: port,
            private_key: if !priv_key.is_empty() {
                priv_key
            } else {
                q.get("privateKey").or_else(|| q.get("private-key")).cloned().unwrap_or_default()
            },
            public_key: pub_k.clone(),
            peer_public_key: pub_k,
            preshared_key: psk,
            local_address: q
                .get("address")
                .or_else(|| q.get("ip"))
                .cloned()
                .unwrap_or_else(|| "172.16.0.2/32".to_string()),
            reserved,
            keepalive,
            amnezia_options: if has_awg { Some(awg) } else { None },
            mtu: Some(q.get("mtu").and_then(|s| s.parse().ok()).unwrap_or(1420)),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 8. MASQUE
    if low.starts_with("masque://") {
        let u = Url::parse(&format!("http://{}", &uri[9..])).ok()?;
        let q = query_map(&u);
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(443);
        let priv_key = percent_decode_plus(u.username(), false);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, true)).unwrap_or_default();
        let keepalive = q
            .get("keepalive")
            .or_else(|| q.get("persistent-keepalive"))
            .or_else(|| q.get("persistent_keepalive"))
            .and_then(|v| v.parse::<u32>().ok());
        let mtu = q.get("mtu").and_then(|s| s.parse().ok()).unwrap_or(1280);
        let sni = q.get("sni").cloned().unwrap_or_else(|| server.clone());
        let insecure = matches!(
            q.get("insecure").or_else(|| q.get("allowInsecure")).or_else(|| q.get("skipCertVerify")).map(|s| s.as_str()),
            Some("1" | "true")
        );
        let transport = q
            .get("transport")
            .or_else(|| q.get("network"))
            .cloned()
            .unwrap_or_else(|| "h2".to_string());
        let address = q
            .get("address")
            .or_else(|| q.get("ip"))
            .cloned()
            .unwrap_or_else(|| "172.16.0.2/32".to_string());
        let remote_dns = q
            .get("remoteDNS")
            .or_else(|| q.get("dns"))
            .cloned()
            .unwrap_or_else(|| "1.1.1.1".to_string());

        let mut awg = AmneziaWgOptions::default();
        let mut has_awg = false;
        if let Some(wn) = q.get("wnoise") { awg.wnoise = Some(wn.clone()); has_awg = true; }
        if let Some(wc) = q.get("wnoisecount").or_else(|| q.get("jc")).and_then(|v| v.parse().ok()) {
            awg.jc = Some(wc);
            has_awg = true;
        }
        if let Some(wp) = q.get("wpayloadsize").or_else(|| q.get("payloadsize")) {
            awg.wpayloadsize = Some(wp.clone());
            if let Some((p1, p2)) = wp.split_once('-') {
                if let (Ok(a), Ok(b)) = (p1.parse::<i64>(), p2.parse::<i64>()) {
                    awg.jmin = Some(a);
                    awg.jmax = Some(b);
                }
            }
            has_awg = true;
        }
        if let Some(wd) = q.get("wnoisedelay") { awg.wnoisedelay = Some(wd.clone()); has_awg = true; }

        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "masque"),
            protocol: "masque".to_string(),
            server,
            server_port: port,
            private_key: if !priv_key.is_empty() {
                priv_key
            } else {
                q.get("privateKey").or_else(|| q.get("private-key")).cloned().unwrap_or_default()
            },
            public_key: q
                .get("publicKey")
                .or_else(|| q.get("public-key"))
                .or_else(|| q.get("publickey"))
                .cloned()
                .unwrap_or_default(),
            local_address: address,
            mtu: Some(mtu),
            remote_dns: Some(remote_dns.clone()),
            dns: vec![remote_dns],
            sni,
            network: transport,
            skip_cert_verify: insecure,
            keepalive,
            amnezia_options: if has_awg { Some(awg) } else { None },
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 9. DNS-based tunneling schemes
    for &dp in DNS_PROTOCOLS {
        let prefix = format!("{}://", dp);
        if low.starts_with(&prefix) {
            let raw_hash = uri
                .split_once('#')
                .map(|(_, h)| percent_decode_plus(h, true))
                .unwrap_or_default();
            return Some(ProxyProfile {
                name: clean_proxy_name(&raw_hash, dp),
                protocol: dp.to_string(),
                is_dns_tunnel: true,
                raw_uri: Some(uri),
                server: "dns-tunnel".to_string(),
                server_port: 53,
                ..Default::default()
            });
        }
    }

    // 10. Shadowsocks (ss://)
    if low.starts_with("ss://") {
        let mut rest = uri[5..].trim().to_string();
        let mut raw_name = String::new();
        if let Some((before, frag)) = rest.split_once('#') {
            raw_name = percent_decode_plus(frag, false);
            rest = before.to_string();
        }
        if let Some((before, _q)) = rest.split_once('?') {
            rest = before.to_string();
        }
        let (auth, host_port) = if let Some((a, hp)) = rest.rsplit_once('@') {
            (a.to_string(), hp.to_string())
        } else {
            let dec = base64_decode_safe(&rest).ok()?;
            let dec_s = String::from_utf8_lossy(&dec).into_owned();
            let (a, hp) = dec_s.rsplit_once('@')?;
            (a.to_string(), hp.to_string())
        };
        let (srv_raw, port_s) = host_port.rsplit_once(':')?;
        let server = srv_raw.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = port_s.parse::<u16>().unwrap_or(8388);
        let (method_raw, password_raw) = if let Some((m, pw)) = auth.split_once(':') {
            (m.to_string(), pw.to_string())
        } else if let Ok(dec) = base64_decode_safe(&auth) {
            let ds = String::from_utf8_lossy(&dec).into_owned();
            if let Some((m, pw)) = ds.split_once(':') {
                (m.to_string(), pw.to_string())
            } else {
                ("aes-128-gcm".to_string(), auth)
            }
        } else {
            ("aes-128-gcm".to_string(), auth)
        };
        let method = percent_decode_plus(&method_raw, false);
        let password = percent_decode_plus(&password_raw, false);
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_name, "ss"),
            protocol: "shadowsocks".to_string(),
            server,
            server_port: port,
            method: method.clone(),
            cipher: method,
            password,
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 11. ShadowsocksR (ssr://)
    if low.starts_with("ssr://") {
        let mut raw = uri[6..].trim().to_string();
        if !raw.contains(':') || !raw.contains('/') {
            if let Ok(dec) = base64_decode_safe(&raw) {
                let ds = String::from_utf8_lossy(&dec).into_owned();
                if !ds.is_empty() {
                    raw = ds;
                }
            }
        }
        let (main_part, query_part) = match raw.split_once("/?") {
            Some((m, q)) => (m, q),
            None => (raw.as_str(), ""),
        };
        let parts: Vec<&str> = main_part.split(':').collect();
        if parts.len() >= 6 {
            let server = parts[0].to_string();
            let port = parts[1].parse::<u16>().ok()?;
            let ssr_proto = parts[2].to_string();
            let method = parts[3].to_string();
            let obfs = parts[4].to_string();
            let password = base64_decode_safe(parts[5])
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| parts[5].to_string());

            let mut name = format!("SSR-{}:{}", server, port);
            let mut obfs_param = String::new();
            let mut proto_param = String::new();
            for (k, v) in url::form_urlencoded::parse(query_part.as_bytes()) {
                match k.as_ref() {
                    "remarks" => {
                        let decoded = base64_decode_safe(&v)
                            .ok()
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_else(|| v.to_string());
                        name = clean_proxy_name(&decoded, "ssr");
                    }
                    "obfsparam" => {
                        obfs_param = base64_decode_safe(&v)
                            .ok()
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_default();
                    }
                    "protoparam" => {
                        proto_param = base64_decode_safe(&v)
                            .ok()
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_default();
                    }
                    _ => {}
                }
            }

            return Some(ProxyProfile {
                name,
                protocol: "shadowsocksr".to_string(),
                server,
                server_port: port,
                method: method.clone(),
                cipher: method,
                password,
                ssr_protocol: ssr_proto,
                protocol_param: proto_param,
                obfs,
                obfs_param,
                raw_uri: Some(uri),
                ..Default::default()
            });
        }
        return None;
    }

    // 12. SOCKS5 / SOCKS
    if low.starts_with("socks5://") || low.starts_with("socks://") {
        let rest = uri.split_once("://")?.1;
        let u = Url::parse(&format!("http://{}", rest)).ok()?;
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = u.port().unwrap_or(1080);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "socks5"),
            protocol: "socks5".to_string(),
            server,
            server_port: port,
            username: percent_decode_plus(u.username(), false),
            password: percent_decode_plus(u.password().unwrap_or(""), false),
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 13. HTTP / HTTPS Proxy
    if low.starts_with("http://") || low.starts_with("https://") {
        let u = Url::parse(&uri).ok()?;
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let is_https = low.starts_with("https://");
        let port = u.port().unwrap_or(if is_https { 443 } else { 80 });
        let raw_user = percent_decode_plus(u.username(), false);
        let raw_pass = percent_decode_plus(u.password().unwrap_or(""), false);
        let has_auth = !raw_user.is_empty() || !raw_pass.is_empty();
        let is_ip = server.parse::<std::net::IpAddr>().is_ok();
        let is_std_web = (port == 80 && !is_https) || (port == 443 && is_https);

        static NON_PROXY_DOMAINS: OnceLock<Regex> = OnceLock::new();
        let re = NON_PROXY_DOMAINS.get_or_init(|| {
            Regex::new(r"(?i)^(?:.*\.)?(?:google\.[a-z.]+|googleusercontent\.com|googleapis\.com|gstatic\.com|apple\.com|icloud\.com|t\.me|telegram\.[a-z.]+|github\.com|githubusercontent\.com|gitlab\.com|workers\.dev|pages\.dev|cloudflare\.com|youtube\.com|youtu\.be|twitter\.com|x\.com|instagram\.com|facebook\.com|wikipedia\.org|play\.google\.com|apps\.apple\.com|drive\.google\.com|bit\.ly|tinyurl\.com|cutt\.ly)$").unwrap()
        });
        if re.is_match(&server) || (!has_auth && is_std_web && !is_ip) {
            return None;
        }
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, "http"),
            protocol: "http".to_string(),
            server,
            server_port: port,
            tls: is_https,
            username: raw_user,
            password: raw_pass,
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    // 14. AnyTLS (full handler with unencoded slash support)
    if low.starts_with("anytls://") {
        return parse_anytls_uri(&uri);
    }

    // 15. NaiveProxy
    if low.starts_with("naive+https://") || low.starts_with("naive://") {
        return parse_naive_uri(&uri);
    }

    // 16. Snell / SSH / ShadowTLS
    if low.starts_with("snell://") || low.starts_with("ssh://") || low.starts_with("shadowtls://") {
        let prefix = low.split("://").next()?;
        let rest = uri.split_once("://")?.1;
        let u = Url::parse(&format!("http://{}", rest)).ok()?;
        let server = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let default_p = if prefix == "ssh" { 22 } else { 443 };
        let port = u.port().unwrap_or(default_p);
        let raw_hash = u.fragment().map(|f| percent_decode_plus(f, false)).unwrap_or_default();
        let user_raw = percent_decode_plus(u.username(), false);
        let pass_raw = percent_decode_plus(u.password().unwrap_or(""), false);
        let pw = if !pass_raw.is_empty() {
            pass_raw.clone()
        } else {
            user_raw.clone()
        };
        return Some(ProxyProfile {
            name: clean_proxy_name(&raw_hash, prefix),
            protocol: prefix.to_string(),
            server,
            server_port: port,
            username: user_raw,
            password: pw.clone(),
            psk: pw,
            raw_uri: Some(uri),
            ..Default::default()
        });
    }

    None
}

pub struct SubscriptionParsed {
    pub format_type: String,
    pub profiles: Vec<ProxyProfile>,
}

pub async fn parse_subscription_text(
    raw_input: &str,
    proxy_mode: &ProxyMode,
    custom_proxy_url: &str,
) -> Result<SubscriptionParsed, DecryptionError> {
    let mut content = raw_input.trim().to_string();
    let is_structured = content.lines().any(|l| {
        let lt = l.trim_start().to_lowercase();
        lt.starts_with("proxies:") || lt.starts_with("proxy-providers:")
    }) || (content.starts_with('{') && content.contains("\"outbounds\""));

    // Extract single subscription URL to fetch if content is not already full structured config
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r#"(?i)https?://[^\s\r\n\t<>"']+"#).unwrap());
    if !is_structured {
        let urls: Vec<String> = url_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
        if !urls.is_empty() {
            let candidate_opt = urls.iter().find(|u| {
                let low = u.to_lowercase();
                if low.contains("t.me/") && !low.contains("/socks?") && !low.contains("/proxy?") {
                    return false;
                }
                if low.contains("play.google.com") || low.contains("apps.apple.com") {
                    return false;
                }
                true
            });
            let has_explicit_raw = content.lines().any(|l| {
                let t = l.trim_start().to_lowercase();
                ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "wireguard://", "tuic://", "anytls://", "vpn://"]
                    .iter()
                    .any(|p| t.starts_with(p))
            });
            if let Some(cand_raw) = candidate_opt {
                let cand = normalize_subscription_url(cand_raw);
                let should_fetch = !has_explicit_raw
                    || cand.contains("drive.google.com")
                    || cand.contains("raw.githubusercontent")
                    || cand.contains("/sub")
                    || cand.contains("#sub")
                    || cand.contains("token=");
                if should_fetch {
                    match fetch_text_with_fallback(&cand, proxy_mode, custom_proxy_url, 12).await {
                        Ok(fetched) => {
                            let ft = fetched.trim().to_string();
                            if ft.len() > 20 && !ft.contains("<!DOCTYPE html>") && !ft.contains("<html") {
                                content = ft;
                            } else if ft.contains("drive.google.com") && ft.contains("confirm=") {
                                if let Some(cap) = Regex::new(r"confirm=([0-9A-Za-z_]+)").unwrap().captures(&ft) {
                                    let confirm_url = format!("{}&confirm={}", cand, &cap[1]);
                                    if let Ok(c_txt) = fetch_text_with_fallback(&confirm_url, proxy_mode, custom_proxy_url, 12).await {
                                        content = c_txt.trim().to_string();
                                    }
                                }
                            } else if urls.len() == 1 && !has_explicit_raw {
                                content = ft;
                            }
                        }
                        Err(e) => {
                            if urls.len() == 1 && !has_explicit_raw {
                                return Err(DecryptionError::plain(format!(
                                    "خطا در دانلود لینک اشتراک: {}",
                                    e
                                )));
                            }
                        }
                    }
                }
            }
        }
    }

    content = content.trim().to_string();

    // JSON-formatted Clash config
    if content.starts_with('{') && (content.contains("\"proxies\"") || content.contains("\"proxy-providers\"")) {
        if let Ok(json_obj) = serde_json::from_str::<Value>(&content) {
            if let Some(arr) = json_obj.get("proxies").and_then(|v| v.as_array()) {
                let proxies: Vec<ProxyProfile> = arr
                    .iter()
                    .filter_map(|v| v.as_object().map(clash_object_to_profile))
                    .collect();
                if !proxies.is_empty() {
                    return Ok(SubscriptionParsed {
                        format_type: "clash_json".to_string(),
                        profiles: proxies,
                    });
                }
            }
        }
    }

    // YAML Clash / Mihomo check
    let looks_yaml = content.lines().any(|l| {
        let lt = l.trim_start().to_lowercase();
        lt.starts_with("proxies:") || lt.starts_with("proxy-providers:") || lt.starts_with("- name:") || lt.starts_with("- server:") || lt.starts_with("- type:")
    }) || (content.contains("port:") && content.contains("rules:"));
    if looks_yaml {
        if let Ok(profiles) = parse_mihomo_yaml_async(&content, proxy_mode, custom_proxy_url).await {
            if !profiles.is_empty() {
                return Ok(SubscriptionParsed {
                    format_type: "mihomo".to_string(),
                    profiles,
                });
            }
        }
    }

    // Sing-box / Xray JSON check
    if content.starts_with('{') && content.contains("\"outbounds\"") {
        if let Ok(json_obj) = serde_json::from_str::<Value>(&content) {
            let has_singbox_type = json_obj
                .get("outbounds")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|o| o.get("type").is_some() && o.get("protocol").is_none()))
                .unwrap_or(false);
            if has_singbox_type {
                let profiles = parse_singbox_json(&content, "Subscription-Singbox")?;
                return Ok(SubscriptionParsed {
                    format_type: "singbox".to_string(),
                    profiles,
                });
            } else if let Some(obs) = json_obj.get("outbounds").and_then(|v| v.as_array()) {
                let mut xray_profiles = Vec::new();
                for ob in obs {
                    let proto = ob
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if proto.is_empty() || matches!(proto.as_str(), "freedom" | "blackhole" | "dns") {
                        continue;
                    }
                    let mut p = unpack_v2ray_json_profile(&serde_json::json!({
                        "name": ob.get("tag").cloned().unwrap_or(Value::Null),
                        "v2rayJson": { "outbounds": [ob] }
                    }));
                    p.raw_outbound = Some(ob.clone());
                    xray_profiles.push(p);
                }
                if !xray_profiles.is_empty() {
                    return Ok(SubscriptionParsed {
                        format_type: "xray_json".to_string(),
                        profiles: xray_profiles,
                    });
                }
            }
        }
    }

    // Try Base64 subscription decode if not containing plain links
    let mut text = content.clone();
    if !content.contains("://")
        && content
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_' | '\r' | '\n' | ' '))
    {
        if let Ok(dec) = base64_decode_safe(&content) {
            let dec_s = String::from_utf8_lossy(&dec).into_owned();
            if dec_s.contains("://") {
                text = dec_s;
            }
        }
    }

    // Split concatenated & parse URIs
    let raw_links = split_concatenated_links(&text);
    let mut parsed_profiles = Vec::new();
    for link in raw_links {
        if link.to_lowercase().starts_with("vpn://") {
            let vpns = parse_amnezia_vpn_uri(&link);
            parsed_profiles.extend(vpns);
        } else if let Some(p) = parse_uri_config(&link) {
            parsed_profiles.push(p);
        }
    }

    Ok(SubscriptionParsed {
        format_type: "subscription".to_string(),
        profiles: parsed_profiles,
    })
}
