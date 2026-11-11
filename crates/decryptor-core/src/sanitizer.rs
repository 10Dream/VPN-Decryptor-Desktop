use crate::crypto_utils::{base64_decode_safe, base64_encode_std};
use crate::models::{FilterStats, ProxyProfile};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

pub const DEFAULT_WARP_PUBKEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
pub const DEFAULT_MASQUE_WARP_PUBKEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==";

pub fn is_blocked_server(lower: &str) -> bool {
    matches!(
        lower,
        "127.0.0.1"
            | "0.0.0.0"
            | "localhost"
            | "::1"
            | "t.me"
            | "telegram.me"
            | "github.com"
            | "raw.githubusercontent.com"
            | "google.com"
            | "example.com"
    )
}

pub fn is_valid_ss_cipher(cipher: &str) -> bool {
    matches!(
        cipher,
        "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "aes-128-gcm"
            | "aes-192-gcm"
            | "aes-256-gcm"
            | "aes-128-ccm"
            | "aes-192-ccm"
            | "aes-256-ccm"
            | "aes-128-gcm-siv"
            | "aes-256-gcm-siv"
            | "chacha20-ietf"
            | "chacha20"
            | "xchacha20"
            | "chacha20-ietf-poly1305"
            | "xchacha20-ietf-poly1305"
            | "chacha8-ietf-poly1305"
            | "xchacha8-ietf-poly1305"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "lea-128-gcm"
            | "lea-192-gcm"
            | "lea-256-gcm"
            | "rabbit128-poly1305"
            | "aegis-128l"
            | "aegis-256"
            | "aez-384"
            | "deoxys-ii-256-128"
            | "rc4-md5"
            | "none"
            | "dummy"
    )
}

pub fn normalize_ec_private_key(priv_key_str: &str) -> String {
    let clean = priv_key_str.trim();
    if clean.starts_with("MIG") {
        if let Ok(buf) = base64_decode_safe(clean) {
            let marker: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            if let Some(idx) = buf.windows(marker.len()).position(|w| w == marker) {
                let search_from = idx + marker.len();
                if let Some(rel_octet) = buf[search_from..].iter().position(|&b| b == 0x04) {
                    let octet_idx = search_from + rel_octet;
                    if octet_idx + 2 < buf.len() {
                        let mut offset = octet_idx + 1;
                        let len_b = buf[offset];
                        offset += 1;
                        if len_b & 0x80 != 0 {
                            offset += (len_b & 0x7f) as usize;
                        }
                        if offset < buf.len() && buf[offset] == 0x30 {
                            return base64_encode_std(&buf[offset..]);
                        }
                    }
                }
            }
        }
    }
    clean.to_string()
}

pub fn remove_control_chars(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            let u = c as u32;
            !((u <= 0x1F)
                || (0x7F..=0x9F).contains(&u)
                || (0x200B..=0x200D).contains(&u)
                || u == 0xFEFF
                || u == 0xFFFD)
        })
        .collect()
}

pub fn is_valid_curve25519_key(key_str: &str) -> bool {
    let clean = key_str.trim();
    if clean.is_empty() {
        return false;
    }
    base64_decode_safe(clean)
        .map(|b| b.len() == 32)
        .unwrap_or(false)
}

pub fn is_troll_string(s: &str) -> bool {
    static TROLL_RE: OnceLock<Regex> = OnceLock::new();
    let re = TROLL_RE.get_or_init(|| {
        Regex::new(r"(?i)دیکریپتور|کیر|کص|گایید|مادر|خواهر").unwrap()
    });
    re.is_match(s)
}

pub fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

pub fn is_valid_server_address(server: &str) -> bool {
    let s = server.trim();
    if s.len() < 3 || s.len() > 253 {
        return false;
    }
    let unbracketed = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(s);
    if unbracketed
        .chars()
        .any(|c| ('\u{0600}'..='\u{06FF}').contains(&c) || c.is_whitespace() || "\\'\"<>{}[]|^`".contains(c))
    {
        return false;
    }
    if s.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return false;
    }
    let lower = s.to_lowercase();
    if is_blocked_server(&lower) {
        return false;
    }
    if matches!(
        lower.as_str(),
        "null" | "undefined" | "none" | "unknown" | "fake" | "test" | "example" | "dummy" | "localhost"
    ) {
        return false;
    }
    if is_troll_string(&lower) {
        return false;
    }

    if is_ipv4(unbracketed) {
        if unbracketed == "0.0.0.0" || unbracketed.starts_with("127.") {
            return false;
        }
        return true;
    }

    if unbracketed.contains(':') {
        let colons = unbracketed.chars().filter(|&c| c == ':').count();
        if colons >= 2 && unbracketed.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return unbracketed != "::" && unbracketed != "::1";
        }
        return false;
    }

    static FQDN_RE: OnceLock<Regex> = OnceLock::new();
    let re = FQDN_RE.get_or_init(|| {
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
    });
    re.is_match(s)
}

pub fn is_valid_sni_or_host(sni: &str) -> bool {
    let s = sni.trim();
    if s.len() < 3 || s.len() > 253 {
        return false;
    }
    if s.chars()
        .any(|c| ('\u{0600}'..='\u{06FF}').contains(&c) || c.is_whitespace() || "\\'\"<>{}[]|^`".contains(c))
    {
        return false;
    }
    if s.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return false;
    }
    is_valid_server_address(s)
}

pub fn is_valid_uuid(uuid: &str) -> bool {
    let u = uuid.trim();
    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    let re = UUID_RE.get_or_init(|| {
        Regex::new(
            r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})$",
        )
        .unwrap()
    });
    re.is_match(u)
}

pub fn clean_proxy_name(name: &str, default_proto: &str) -> String {
    let fallback = default_proto.to_uppercase();
    if name.trim().is_empty() {
        return fallback;
    }
    let clean = remove_control_chars(name).trim().to_string();
    static STRIP_URI_RE: OnceLock<Regex> = OnceLock::new();
    let uri_re = STRIP_URI_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|hysteria|wireguard|wg|tuic|snell|socks|http)://[^\s]+").unwrap()
    });
    let no_uri = uri_re.replace_all(&clean, "");
    let replaced: String = no_uri
        .trim()
        .chars()
        .map(|c| {
            if ":#[]{},&*?|<>=!%@\\".contains(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed: String = replaced.split_whitespace().collect::<Vec<_>>().join(" ");

    static CLEAN_TROLL_RE: OnceLock<Regex> = OnceLock::new();
    let troll_re = CLEAN_TROLL_RE.get_or_init(|| {
        Regex::new(r"(?i)دیکریپتور|کیرم|کص|گاییدم|مادرتو|خواهرتو").unwrap()
    });
    let final_s = if troll_re.is_match(&collapsed) {
        fallback.clone()
    } else {
        collapsed
    };
    if final_s.is_empty() { fallback } else { final_s }
}

pub fn escape_lone_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let valid_hex = i + 2 < bytes.len()
                && (bytes[i + 1] as char).is_ascii_hexdigit()
                && (bytes[i + 2] as char).is_ascii_hexdigit();
            if valid_hex {
                out.push('%');
            } else {
                out.push_str("%25");
            }
            i += 1;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

pub fn heal_proxy(p: &mut ProxyProfile) {
    let net = if p.network.trim().is_empty() {
        "tcp".to_string()
    } else {
        p.network.trim().to_lowercase()
    };

    if !p.flow.trim().is_empty() {
        let raw_flow = p.flow.trim().to_lowercase();
        if net != "tcp" || !raw_flow.contains("vision") {
            p.flow.clear();
        } else {
            p.flow = "xtls-rprx-vision".to_string();
        }
    }

    if !p.path.trim().is_empty() {
        p.path = escape_lone_percent(p.path.trim());
    }

    let is_tls = p.tls
        || p.security.eq_ignore_ascii_case("tls")
        || p.reality
        || p.security.eq_ignore_ascii_case("reality");

    if is_tls && p.sni.trim().is_empty() {
        let srv = p.server.trim();
        if is_valid_server_address(srv) && !is_ipv4(srv) && !srv.contains(':') {
            p.sni = srv.to_string();
        }
    }

    if net == "ws" && p.path.trim().is_empty() {
        p.path = "/".to_string();
    }

    if !p.obfs.is_empty() && p.obfs_password.trim().is_empty() {
        p.obfs.clear();
        p.obfs_password.clear();
    }

    if p.server_port == 0 {
        p.server_port = 443;
    }

    if is_tls && p.fingerprint.trim().is_empty() {
        p.fingerprint = "chrome".to_string();
    }

    if p.protocol.eq_ignore_ascii_case("vmess") && p.alter_id.is_none() {
        p.alter_id = Some(0);
    }
}

pub fn get_connection_fingerprint(p: &ProxyProfile) -> String {
    let proto = p.protocol.to_lowercase().trim().to_string();
    let server = p.server.to_lowercase().trim().to_string();
    let port = p.server_port;
    let net = if p.network.trim().is_empty() {
        "tcp".to_string()
    } else {
        p.network.to_lowercase().trim().to_string()
    };

    let mut critical: BTreeMap<&'static str, Value> = BTreeMap::new();
    critical.insert("proto", Value::String(proto.clone()));
    critical.insert("server", Value::String(server));
    critical.insert("port", Value::Number(port.into()));
    critical.insert("net", Value::String(net.clone()));

    let auth = if !p.uuid.trim().is_empty() {
        p.uuid.trim()
    } else if !p.password.trim().is_empty() {
        p.password.trim()
    } else if !p.private_key.trim().is_empty() {
        p.private_key.trim()
    } else if !p.psk.trim().is_empty() {
        p.psk.trim()
    } else {
        ""
    };
    if !auth.is_empty() {
        critical.insert("auth", Value::String(auth.to_string()));
    }
    if proto == "anytls" {
        critical.insert("auth", Value::String(p.password.trim().to_string()));
    }

    let cipher = if !p.cipher.trim().is_empty() {
        p.cipher.to_lowercase().trim().to_string()
    } else {
        p.method.to_lowercase().trim().to_string()
    };
    if !cipher.is_empty() {
        critical.insert("cipher", Value::String(cipher));
    }

    let flow = p.flow.to_lowercase().trim().to_string();
    if !flow.is_empty() && net == "tcp" {
        critical.insert("flow", Value::String(flow));
    }

    if proto == "vmess" {
        critical.insert("alterId", Value::Number(p.alter_id.unwrap_or(0).into()));
    }

    let sni = if !p.sni.trim().is_empty() {
        p.sni.to_lowercase().trim().to_string()
    } else {
        p.host.to_lowercase().trim().to_string()
    };
    if !sni.is_empty() {
        critical.insert("sni", Value::String(sni));
    }
    if !p.public_key.trim().is_empty() && proto != "wireguard" && proto != "wg" && proto != "masque"
    {
        critical.insert("pbk", Value::String(p.public_key.trim().to_string()));
    }
    if !p.short_id.trim().is_empty() {
        critical.insert("sid", Value::String(p.short_id.trim().to_string()));
    }
    if !p.path.trim().is_empty() {
        critical.insert("path", Value::String(p.path.trim().to_string()));
    }
    if !p.service_name.trim().is_empty() {
        critical.insert("serviceName", Value::String(p.service_name.trim().to_string()));
    }
    if !p.obfs.trim().is_empty() {
        critical.insert("obfs", Value::String(p.obfs.trim().to_string()));
    }
    if !p.obfs_password.trim().is_empty() {
        critical.insert("obfsPassword", Value::String(p.obfs_password.trim().to_string()));
    }
    if proto == "wireguard" || proto == "wg" {
        let peer_pub = if !p.peer_public_key.trim().is_empty() {
            p.peer_public_key.trim()
        } else {
            p.public_key.trim()
        };
        if !peer_pub.is_empty() {
            critical.insert("peerPub", Value::String(peer_pub.to_string()));
        }
        if let Some(ref res) = p.reserved {
            let rs: Vec<String> = res.iter().map(|x| x.to_string()).collect();
            critical.insert("reserved", Value::String(rs.join(",")));
        }
    }
    if proto == "masque" {
        if !p.public_key.trim().is_empty() {
            critical.insert("pubKey", Value::String(p.public_key.trim().to_string()));
        }
        if !p.private_key.trim().is_empty() {
            critical.insert("privKey", Value::String(p.private_key.trim().to_string()));
        }
    }

    serde_json::to_string(&critical).unwrap_or_default()
}

fn json_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn json_u16(v: Option<&Value>) -> Option<u16> {
    match v {
        Some(Value::Number(n)) => n.as_u64().and_then(|x| u16::try_from(x).ok()),
        Some(Value::String(s)) => s.trim().parse::<u16>().ok(),
        _ => None,
    }
}

/// Unpack NapsternetV / NPVT / NPVS / EHI raw JSON profile objects (including nested v2rayJson / configJson / v2rayProfile).
pub fn unpack_v2ray_json_profile(raw: &Value) -> ProxyProfile {
    let mut out = ProxyProfile::default();
    let Some(obj) = raw.as_object() else {
        return out;
    };

    let vp = obj
        .get("v2rayProfile")
        .or_else(|| obj.get("profile"))
        .and_then(|v| v.as_object())
        .unwrap_or(obj);

    let get = |k: &str| vp.get(k).or_else(|| obj.get(k));

    // Preserve expiry raw if present on item or nested settings/policy
    out.expiry_raw = ["expiryDate", "expiresAt", "expiryTime", "Expiration Date", "configExpiryTimestamp", "EXPIRY_DATE"]
        .iter()
        .find_map(|k| get(k).map(|v| json_str(Some(v))).filter(|s| !s.is_empty()))
        .or_else(|| {
            obj.get("settings")
                .and_then(|s| s.get("expiryDate").or_else(|| s.get("expiresAt")).or_else(|| s.get("expiryTime")))
                .map(|v| json_str(Some(v)))
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            obj.get("policy")
                .and_then(|p| p.get("expiresAt"))
                .map(|v| json_str(Some(v)))
                .filter(|s| !s.is_empty())
        });

    out.name = json_str(obj.get("name").or_else(|| vp.get("remarks")).or_else(|| obj.get("remarks")));
    out.protocol = json_str(get("protocol").or_else(|| get("type"))).to_lowercase();

    // Unpack embedded v2rayJson / configJson first
    if let Some(raw_vj) = vp.get("v2rayJson").or_else(|| vp.get("configJson")).or_else(|| obj.get("v2rayJson")) {
        let vj_opt: Option<Value> = match raw_vj {
            Value::String(s) => serde_json::from_str(s).ok(),
            other => Some(other.clone()),
        };
        if let Some(vj) = vj_opt {
            if let Some(obs) = vj.get("outbounds").and_then(|v| v.as_array()) {
                let target_ob = obs
                    .iter()
                    .find(|o| {
                        o.get("tag").and_then(|t| t.as_str()) == Some("proxy")
                            || matches!(
                                o.get("protocol").and_then(|p| p.as_str()),
                                Some("trojan" | "vless" | "vmess" | "shadowsocks" | "socks")
                            )
                    })
                    .or_else(|| obs.first());

                if let Some(ob) = target_ob {
                    let op = json_str(ob.get("protocol")).to_lowercase();
                    if !op.is_empty() {
                        out.protocol = op;
                    }
                    if let Some(settings) = ob.get("settings") {
                        if let Some(s) = settings.get("servers").and_then(|v| v.as_array()).and_then(|a| a.first()) {
                            let addr = json_str(s.get("address"));
                            if !addr.is_empty() { out.server = addr; }
                            if let Some(pt) = json_u16(s.get("port")) { out.server_port = pt; }
                            let pw = json_str(s.get("password"));
                            if !pw.is_empty() { out.password = pw; }
                            let cip = json_str(s.get("method").or_else(|| s.get("cipher")));
                            if !cip.is_empty() { out.cipher = cip; }
                        }
                        if let Some(vn) = settings.get("vnext").and_then(|v| v.as_array()).and_then(|a| a.first()) {
                            let addr = json_str(vn.get("address"));
                            if !addr.is_empty() { out.server = addr; }
                            if let Some(pt) = json_u16(vn.get("port")) { out.server_port = pt; }
                            if let Some(u) = vn.get("users").and_then(|v| v.as_array()).and_then(|a| a.first()) {
                                let id = json_str(u.get("id").or_else(|| u.get("uuid")));
                                if !id.is_empty() { out.uuid = id; }
                                if let Some(aid) = u.get("alterId").and_then(|v| v.as_u64()) {
                                    out.alter_id = Some(aid as u32);
                                }
                                let fl = json_str(u.get("flow"));
                                if !fl.is_empty() { out.flow = fl; }
                                let enc = json_str(u.get("encryption"));
                                if !enc.is_empty() { out.cipher = enc; }
                            }
                        }
                    }
                    if let Some(ss) = ob.get("streamSettings") {
                        let net = json_str(ss.get("network"));
                        if !net.is_empty() { out.network = net; }
                        let sec = json_str(ss.get("security"));
                        if !sec.is_empty() {
                            out.security = sec.clone();
                            if sec == "tls" { out.tls = true; }
                            else if sec == "reality" { out.tls = true; out.reality = true; }
                        }
                        if let Some(ts) = ss.get("tlsSettings") {
                            let sn = json_str(ts.get("serverName"));
                            if !sn.is_empty() { out.sni = sn; }
                            let fp = json_str(ts.get("fingerprint"));
                            if !fp.is_empty() { out.fingerprint = fp; }
                            if let Some(Value::Array(arr)) = ts.get("alpn") {
                                out.alpn = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                            }
                        }
                        if let Some(rs) = ss.get("realitySettings") {
                            let sn = json_str(rs.get("serverName"));
                            if !sn.is_empty() { out.sni = sn; }
                            let pk = json_str(rs.get("publicKey"));
                            if !pk.is_empty() { out.public_key = pk; }
                            let sid = json_str(rs.get("shortId"));
                            if !sid.is_empty() { out.short_id = sid; }
                            let fp = json_str(rs.get("fingerprint"));
                            if !fp.is_empty() { out.fingerprint = fp; }
                        }
                        if let Some(ws) = ss.get("wsSettings") {
                            let p = json_str(ws.get("path"));
                            if !p.is_empty() { out.path = p; }
                            let h = json_str(ws.get("headers").and_then(|x| x.get("Host")).or_else(|| ws.get("host")));
                            if !h.is_empty() { out.host = h; }
                        }
                        if let Some(grpc) = ss.get("grpcSettings") {
                            let sn = json_str(grpc.get("serviceName"));
                            if !sn.is_empty() { out.service_name = sn; }
                        }
                        if let Some(hs) = ss.get("httpSettings") {
                            let p = json_str(hs.get("path"));
                            if !p.is_empty() { out.path = p; }
                            let h = json_str(hs.get("host"));
                            if !h.is_empty() { out.host = h; }
                        }
                    }
                }
            }
        }
    }

    // Apply structured NapsternetV / NPV fields if present
    let addr_raw = json_str(get("server").or_else(|| get("address")).or_else(|| get("add")));
    if out.server.is_empty() && !addr_raw.is_empty() {
        if addr_raw.contains(':') && !addr_raw.starts_with('[') && addr_raw.matches(':').count() == 1 {
            if let Some((h, pt)) = addr_raw.split_once(':') {
                out.server = h.trim().to_string();
                if let Ok(p) = pt.trim().parse::<u16>() {
                    out.server_port = p;
                }
            }
        } else {
            out.server = addr_raw.trim().to_string();
        }
    }
    if out.server_port == 0 {
        if let Some(pt) = json_u16(get("serverPort").or_else(|| get("port"))) {
            out.server_port = pt;
        } else {
            out.server_port = 443;
        }
    }
    if out.password.is_empty() {
        out.password = json_str(get("password")).trim().to_string();
    }
    if out.uuid.is_empty() {
        out.uuid = json_str(get("uuid").or_else(|| get("id"))).trim().to_string();
    }
    if out.uuid.is_empty() && is_valid_uuid(&out.password) {
        out.uuid = out.password.clone();
    }
    if out.network.is_empty() {
        out.network = json_str(get("network").or_else(|| get("net"))).trim().to_lowercase();
    }
    if out.security.is_empty() {
        let sec = json_str(get("security")).trim().to_lowercase();
        if !sec.is_empty() {
            out.security = sec.clone();
            if sec == "tls" { out.tls = true; }
            if sec == "reality" { out.tls = true; out.reality = true; }
        }
    }
    if let Some(true) = get("tls").and_then(|v| v.as_bool()) { out.tls = true; }
    if let Some(true) = get("reality").and_then(|v| v.as_bool()) { out.reality = true; out.tls = true; }
    if out.sni.is_empty() {
        out.sni = json_str(get("sni").or_else(|| get("serverName")).or_else(|| get("servername"))).trim().to_string();
    }
    if out.host.is_empty() {
        out.host = json_str(get("host")).trim().to_string();
    }
    if out.path.is_empty() {
        out.path = json_str(get("path")).trim().to_string();
    }
    if out.fingerprint.is_empty() {
        out.fingerprint = json_str(get("fingerPrint").or_else(|| get("fingerprint")).or_else(|| get("fp"))).trim().to_string();
    }
    if out.public_key.is_empty() {
        out.public_key = json_str(get("publicKey").or_else(|| get("pbk"))).trim().to_string();
    }
    if out.short_id.is_empty() {
        out.short_id = json_str(get("shortId").or_else(|| get("sid"))).trim().to_string();
    }
    if out.spider_x.is_empty() {
        out.spider_x = json_str(get("spiderX").or_else(|| get("spx"))).trim().to_string();
    }
    if out.flow.is_empty() {
        out.flow = json_str(get("flow")).trim().to_string();
    }
    if out.cipher.is_empty() {
        out.cipher = json_str(get("method").or_else(|| get("cipher")).or_else(|| get("encryption"))).trim().to_string();
    }
    if out.method.is_empty() {
        out.method = out.cipher.clone();
    }
    if out.alter_id.is_none() {
        if let Some(aid) = get("alterId").or_else(|| get("aid")).and_then(|v| v.as_u64()) {
            out.alter_id = Some(aid as u32);
        }
    }
    out.config_type = vp.get("configType").and_then(|v| v.as_i64());

    let cur_p = out.protocol.trim().to_string();
    if cur_p.is_empty()
        || matches!(
            cur_p.as_str(),
            "v2ray" | "v2ray_uri" | "proxy" | "custom" | "generic" | "raw" | "unknown"
        )
    {
        let mut inferred = "";
        if let Some(ct) = out.config_type {
            inferred = match ct {
                6 => {
                    if !out.public_key.is_empty() || out.reality || out.security == "reality" {
                        "vless"
                    } else if !out.password.is_empty() && !is_valid_uuid(&out.password) {
                        "trojan"
                    } else {
                        "vless"
                    }
                }
                5 => {
                    if !out.uuid.is_empty() || (!out.password.is_empty() && is_valid_uuid(&out.password)) {
                        if out.alter_id.unwrap_or(0) > 0 { "vmess" } else { "vless" }
                    } else if !out.password.is_empty() && !is_valid_uuid(&out.password) {
                        "trojan"
                    } else {
                        "vless"
                    }
                }
                4 => "socks5",
                3 => "shadowsocks",
                1 | 2 => "vmess",
                _ => "",
            };
        }
        if inferred.is_empty() {
            inferred = if !out.public_key.is_empty() || out.reality || !out.flow.is_empty() {
                "vless"
            } else if out.alter_id.unwrap_or(0) > 0 {
                "vmess"
            } else if !out.cipher.is_empty() && !out.password.is_empty() {
                "shadowsocks"
            } else if !out.uuid.is_empty() {
                "vless"
            } else if !out.password.is_empty() {
                if is_valid_uuid(&out.password) { "vless" } else { "trojan" }
            } else {
                "vless"
            };
        }
        out.protocol = inferred.to_string();
    }

    out
}

pub fn validate_and_sanitize_proxy(raw_p: &ProxyProfile) -> Option<ProxyProfile> {
    if raw_p.protocol == "note" || raw_p.server == "ehi-locked" {
        return None;
    }

    let mut p = raw_p.clone();
    let mut proto = p.protocol.to_lowercase().trim().to_string();
    if proto.is_empty()
        || matches!(
            proto.as_str(),
            "proxy" | "v2ray" | "v2ray_uri" | "generic" | "custom" | "raw" | "unknown"
        )
    {
        if let Some(ct) = p.config_type {
            proto = match ct {
                6 => "trojan".to_string(),
                5 => {
                    if !p.password.is_empty()
                        && !is_valid_uuid(&p.password)
                        && !p.reality
                        && p.public_key.is_empty()
                    {
                        "trojan".to_string()
                    } else {
                        "vless".to_string()
                    }
                }
                4 => "socks5".to_string(),
                3 => "shadowsocks".to_string(),
                1 | 2 => "vmess".to_string(),
                _ => String::new(),
            };
        }
        if proto.is_empty() {
            proto = if p.reality
                || p.security == "reality"
                || !p.flow.is_empty()
                || !p.public_key.is_empty()
            {
                "vless".to_string()
            } else if p.alter_id.is_some() {
                "vmess".to_string()
            } else if !p.password.is_empty() && p.uuid.is_empty() && p.cipher.is_empty() {
                "trojan".to_string()
            } else if !p.cipher.is_empty() && (!p.password.is_empty() || !p.psk.is_empty()) {
                "shadowsocks".to_string()
            } else {
                "vless".to_string()
            };
        }
    }

    let server = p.server.trim().to_string();
    if server.is_empty() || p.server_port == 0 {
        return None;
    }
    if !is_valid_server_address(&server) {
        return None;
    }

    p.protocol = proto.clone();
    p.server = server
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&server)
        .to_string();
    p.name = clean_proxy_name(&p.name, &proto);

    heal_proxy(&mut p);

    // Clean SNI and Host
    if !p.sni.is_empty() {
        let sni_clean = p
            .sni
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(p.sni.trim())
            .to_string();
        if !is_valid_sni_or_host(&sni_clean) || sni_clean.contains(':') || is_ipv4(&sni_clean) {
            p.sni.clear();
        } else {
            p.sni = sni_clean;
        }
    }
    if !p.host.is_empty() {
        let host_clean = p
            .host
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(p.host.trim())
            .to_string();
        if !is_valid_sni_or_host(&host_clean) {
            p.host.clear();
        } else {
            p.host = host_clean;
        }
    }

    let is_tls = p.tls
        || p.security.eq_ignore_ascii_case("tls")
        || p.reality
        || p.security.eq_ignore_ascii_case("reality");
    if is_tls && p.sni.trim().is_empty() {
        if is_valid_server_address(&p.server) && !is_ipv4(&p.server) && !p.server.contains(':') {
            p.sni = p.server.clone();
        }
    }

    if is_troll_string(&p.password) || is_troll_string(&p.username) || is_troll_string(&p.uuid) {
        return None;
    }

    match proto.as_str() {
        "ssh" => {
            p.protocol = "ssh".to_string();
            if p.username.trim().is_empty() {
                return None;
            }
            p.username = p.username.trim().to_string();
            p.password = p.password.trim().to_string();
        }
        "vless" => {
            let uuid = if !p.uuid.trim().is_empty() {
                p.uuid.trim().to_string()
            } else {
                p.password.trim().to_string()
            };
            if !is_valid_uuid(&uuid) {
                return None;
            }
            p.uuid = uuid;

            if p.reality || p.security == "reality" {
                let pbk = p.public_key.trim().to_string();
                if !pbk.is_empty() && is_valid_curve25519_key(&pbk) {
                    p.public_key = pbk;
                    p.reality = true;
                    p.security = "reality".to_string();
                    let sid = p.short_id.trim();
                    if !sid.is_empty()
                        && sid.len() <= 16
                        && sid.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        p.short_id = if sid.len() % 2 != 0 {
                            format!("0{}", sid)
                        } else {
                            sid.to_string()
                        };
                    } else {
                        p.short_id.clear();
                    }
                } else {
                    p.reality = false;
                    p.security = "tls".to_string();
                    p.tls = true;
                }
            }
        }
        "vmess" => {
            let uuid = if !p.uuid.trim().is_empty() {
                p.uuid.trim().to_string()
            } else {
                p.password.trim().to_string()
            };
            if !is_valid_uuid(&uuid) {
                return None;
            }
            p.uuid = uuid;
            if p.security.is_empty() {
                p.security = "auto".to_string();
            }
            if p.alter_id.is_none() {
                p.alter_id = Some(0);
            }
        }
        "trojan" => {
            if p.password.trim().is_empty() && !p.uuid.trim().is_empty() {
                p.password = p.uuid.trim().to_string();
            }
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
        }
        "shadowsocks" | "ss" => {
            p.protocol = "shadowsocks".to_string();
            if p.password.trim().is_empty() && !p.psk.trim().is_empty() {
                p.password = p.psk.trim().to_string();
            }
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
            let mut cipher = if !p.cipher.trim().is_empty() {
                p.cipher.to_lowercase().trim().to_string()
            } else if !p.method.trim().is_empty() {
                p.method.to_lowercase().trim().to_string()
            } else {
                "aes-128-gcm".to_string()
            };
            if cipher == "chacha20" {
                cipher = "chacha20-ietf-poly1305".to_string();
            }
            if !is_valid_ss_cipher(&cipher) {
                cipher = "aes-128-gcm".to_string();
            }
            p.method = cipher;
        }
        "shadowsocksr" | "ssr" => {
            p.protocol = "shadowsocksr".to_string();
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
            if p.ssr_protocol.is_empty() {
                p.ssr_protocol = "origin".to_string();
            }
            if p.obfs.is_empty() {
                p.obfs = "plain".to_string();
            }
        }
        "hysteria2" | "hy2" => {
            p.protocol = "hysteria2".to_string();
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
        }
        "hysteria" => {
            let auth = if !p.auth_str.trim().is_empty() {
                p.auth_str.trim().to_string()
            } else {
                p.password.trim().to_string()
            };
            if auth.is_empty() {
                return None;
            }
            p.auth_str = auth;
        }
        "wireguard" | "wg" => {
            p.protocol = "wireguard".to_string();
            let priv_k = p.private_key.trim().to_string();
            if priv_k.is_empty() || !is_valid_curve25519_key(&priv_k) {
                return None;
            }
            p.private_key = priv_k;
            let raw_pub = if !p.peer_public_key.trim().is_empty() {
                p.peer_public_key.trim()
            } else {
                p.public_key.trim()
            };
            let pub_k = if !raw_pub.is_empty() && is_valid_curve25519_key(raw_pub) {
                raw_pub.to_string()
            } else {
                DEFAULT_WARP_PUBKEY.to_string()
            };
            p.public_key = pub_k;
            if p.local_address.trim().is_empty() {
                p.local_address = "172.16.0.2/32".to_string();
            }
            if p.mtu.is_none() {
                p.mtu = Some(1420);
            }
        }
        "openvpn" => {
            p.protocol = "openvpn".to_string();
            let has_user_pass = !p.username.trim().is_empty() && !p.password.trim().is_empty();
            let has_cert_key = p.cert.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                && p.key.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
            if !has_user_pass && !has_cert_key {
                return None;
            }
            if !has_cert_key {
                p.cert = None;
                p.key = None;
            }
        }
        "tuic" => {
            p.uuid = p.uuid.trim().to_string();
            p.password = p.password.trim().to_string();
            if p.uuid.is_empty() || p.password.is_empty() {
                return None;
            }
        }
        "snell" => {
            let psk = if !p.psk.trim().is_empty() {
                p.psk.trim().to_string()
            } else {
                p.password.trim().to_string()
            };
            if psk.is_empty() {
                return None;
            }
            p.psk = psk;
        }
        "anytls" => {
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
            p.tls = true;
            if p.sni.is_empty() {
                p.sni = p.server.clone();
            }
            if p.fingerprint.is_empty() {
                p.fingerprint = "chrome".to_string();
            }
            if p.alpn.is_empty() {
                p.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
            }
            if p.idle_session_check_interval.is_none() {
                p.idle_session_check_interval = Some("30s".to_string());
            }
            if p.idle_session_timeout.is_none() {
                p.idle_session_timeout = Some("30s".to_string());
            }
            if p.min_idle_session.is_none() {
                p.min_idle_session = Some(0);
            }
        }
        "naive" => {
            p.password = p.password.trim().to_string();
            if p.password.is_empty() {
                return None;
            }
            p.username = p.username.trim().to_string();
            p.tls = true;
            if p.sni.is_empty() {
                p.sni = p.server.clone();
            }
        }
        "masque" => {
            p.protocol = "masque".to_string();
            let raw_priv = p.private_key.trim();
            if raw_priv.is_empty() {
                return None;
            }
            p.private_key = normalize_ec_private_key(raw_priv);
            if p.public_key.trim().is_empty() {
                p.public_key = DEFAULT_MASQUE_WARP_PUBKEY.to_string();
            }
            if p.network.is_empty() {
                p.network = "h2".to_string();
            }
            if p.sni.is_empty() {
                p.sni = "consumer-masque.cloudflareclient.com".to_string();
            }
            if p.local_address.is_empty() {
                p.local_address = "172.16.0.2".to_string();
            }
            if p.udp.is_none() {
                p.udp = Some(true);
            }
            if p.remote_dns_resolve.is_none() {
                p.remote_dns_resolve = Some(true);
            }
            if p.dns.is_empty() {
                p.dns = vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()];
            }
        }
        "http" | "https" => {
            p.protocol = "http".to_string();
            let s = p.server.to_lowercase();
            let ip_or_v6 = is_ipv4(&s) || s.contains(':');
            let std_web_port = p.server_port == 80 || p.server_port == 443;
            let has_auth = !p.username.is_empty() || !p.password.is_empty();

            static NON_PROXY_HTTP_RE: OnceLock<Regex> = OnceLock::new();
            let re = NON_PROXY_HTTP_RE.get_or_init(|| {
                Regex::new(r"(?i)^(?:.*\.)?(?:google\.[a-z.]+|googleusercontent\.com|googleapis\.com|gstatic\.com|apple\.com|icloud\.com|t\.me|telegram\.[a-z.]+|github\.com|githubusercontent\.com|gitlab\.com|workers\.dev|pages\.dev|cloudflare\.com|youtube\.com|youtu\.be|twitter\.com|x\.com|instagram\.com|facebook\.com|wikipedia\.org|openai\.com|chat\.openai\.com|zoom\.us|speedtest\.net|speedtest\.[a-z.]+|ac\.ir|gov\.ir|org\.ir|ir|blogstar\.net|telewebion\.com|digikala\.com|snapp\.ir|rubika\.ir|bale\.ai|eitaa\.com|aparat\.com)$").unwrap()
            });
            if re.is_match(&s) {
                return None;
            }
            if !ip_or_v6 && std_web_port && !has_auth {
                return None;
            }
        }
        _ => {}
    }

    Some(p)
}

pub fn filter_and_deduplicate_with_stats(
    proxies: &[ProxyProfile],
    filter_duplicates: bool,
    filter_broken: bool,
) -> (Vec<ProxyProfile>, FilterStats) {
    let mut valid_proxies = Vec::new();
    let mut seen_fps = HashSet::new();
    let mut rejected = 0usize;
    let mut duplicates = 0usize;
    let mut proto_counts: BTreeMap<String, usize> = BTreeMap::new();

    for p in proxies {
        let final_opt = validate_and_sanitize_proxy(p);
        let final_proxy = match final_opt {
            Some(vp) => vp,
            None => {
                if filter_broken {
                    rejected += 1;
                    continue;
                }
                let mut raw = p.clone();
                let mut rp = raw.protocol.to_lowercase().trim().to_string();
                if rp.is_empty()
                    || matches!(rp.as_str(), "v2ray" | "proxy" | "custom" | "raw" | "unknown")
                {
                    rp = if raw.config_type == Some(3) || !raw.cipher.is_empty() {
                        "shadowsocks".to_string()
                    } else if raw.config_type == Some(4) {
                        "socks5".to_string()
                    } else if raw.config_type == Some(6) {
                        "trojan".to_string()
                    } else if matches!(raw.config_type, Some(1 | 2)) || raw.alter_id.is_some() {
                        "vmess".to_string()
                    } else if raw.reality || raw.security == "reality" || !raw.public_key.is_empty() || !raw.uuid.is_empty() {
                        "vless".to_string()
                    } else if !raw.password.is_empty() && raw.uuid.is_empty() {
                        "trojan".to_string()
                    } else {
                        "vless".to_string()
                    };
                }
                raw.protocol = rp;
                if raw.server.trim().is_empty() {
                    raw.server = "127.0.0.1".to_string();
                } else {
                    raw.server = raw
                        .server
                        .trim()
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(raw.server.trim())
                        .to_string();
                }
                if raw.server_port == 0 {
                    raw.server_port = 443;
                }
                raw.name = clean_proxy_name(&raw.name, "Raw-Proxy");
                raw
            }
        };

        let fp = get_connection_fingerprint(&final_proxy);
        if filter_duplicates && !seen_fps.insert(fp) {
            duplicates += 1;
            continue;
        }

        let mut pr = final_proxy.protocol.to_uppercase();
        if pr.is_empty()
            || matches!(
                pr.as_str(),
                "PROXY" | "RAW-PROXY" | "GENERIC" | "V2RAY" | "V2RAY_URI" | "CUSTOM" | "UNKNOWN"
            )
        {
            pr = if !final_proxy.uuid.is_empty() || final_proxy.reality || !final_proxy.public_key.is_empty() {
                "VLESS".to_string()
            } else if final_proxy.alter_id.unwrap_or(0) > 0 {
                "VMESS".to_string()
            } else if !final_proxy.password.is_empty() && final_proxy.cipher.is_empty() {
                "TROJAN".to_string()
            } else if !final_proxy.cipher.is_empty() {
                "SHADOWSOCKS".to_string()
            } else {
                "VLESS".to_string()
            };
        }
        *proto_counts.entry(pr).or_insert(0) += 1;
        valid_proxies.push(final_proxy);
    }

    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for p in &mut valid_proxies {
        let base = if p.name.trim().is_empty() {
            format!("{}-{}", p.protocol.to_uppercase(), p.server)
        } else {
            p.name.clone()
        };
        let cnt = name_counts.entry(base.clone()).or_insert(0);
        if *cnt == 0 {
            *cnt = 1;
            p.name = base;
        } else {
            *cnt += 1;
            p.name = format!("{}-{}", base, *cnt);
        }
    }

    let stats = FilterStats {
        total: proxies.len(),
        valid: valid_proxies.len(),
        rejected,
        duplicates,
        expired_count: 0,
        proto_counts,
        filter_duplicates,
        filter_broken,
    };
    (valid_proxies, stats)
}
