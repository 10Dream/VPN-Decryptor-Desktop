use crate::models::ProxyProfile;
use crate::parsers::subscription::is_dns_protocol;
use crate::sanitizer::{clean_proxy_name, filter_and_deduplicate_with_stats, remove_control_chars};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};

fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let ch = *b as char;
        if ch.is_ascii_alphanumeric()
            || matches!(ch, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')')
        {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn bracket_host(host: &str) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') && !h.ends_with(']') {
        format!("[{}]", h)
    } else {
        h.to_string()
    }
}

fn append_query_pairs(pairs: &[(String, String)]) -> String {
    let items: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(v)))
        .collect();
    if items.is_empty() {
        String::new()
    } else {
        format!("?{}", items.join("&"))
    }
}

pub fn profile_to_xray_uri(p: &ProxyProfile) -> Option<String> {
    if p.is_dns_tunnel || is_dns_protocol(&p.protocol) {
        return None;
    }
    let proto = p.protocol.to_lowercase();
    let proto = proto.trim();
    let host = bracket_host(&p.server);
    let port = if p.server_port == 0 { 443 } else { p.server_port };
    let name = clean_proxy_name(&p.name, &format!("{}-{}", proto.to_uppercase(), p.server));
    let frag = encode_uri_component(&name);

    match proto {
        "vless" => {
            if p.uuid.trim().is_empty() {
                return p.raw_uri.clone();
            }
            let mut q = Vec::new();
            let enc = if p.encryption.trim().is_empty() {
                "none"
            } else {
                p.encryption.trim()
            };
            q.push(("encryption".into(), enc.into()));

            let sec = if p.reality || p.security == "reality" {
                "reality"
            } else if p.tls || p.security == "tls" {
                "tls"
            } else {
                "none"
            };
            q.push(("security".into(), sec.into()));

            let net = if p.network.trim().is_empty() {
                "tcp"
            } else {
                p.network.trim()
            };
            q.push(("type".into(), net.into()));

            if sec != "none" {
                if !p.sni.is_empty() {
                    q.push(("sni".into(), p.sni.clone()));
                }
                if !p.fingerprint.is_empty() {
                    q.push(("fp".into(), p.fingerprint.clone()));
                }
                if !p.alpn.is_empty() {
                    q.push(("alpn".into(), p.alpn.join(",")));
                }
                if p.skip_cert_verify && sec != "reality" {
                    q.push(("allowInsecure".into(), "1".into()));
                }
            }
            if sec == "reality" {
                if !p.public_key.is_empty() {
                    q.push(("pbk".into(), p.public_key.clone()));
                }
                if !p.short_id.is_empty() {
                    q.push(("sid".into(), p.short_id.clone()));
                }
                if !p.spider_x.is_empty() {
                    q.push(("spx".into(), p.spider_x.clone()));
                }
            }
            if !p.flow.is_empty() {
                q.push(("flow".into(), p.flow.clone()));
            }
            match net {
                "ws" | "httpupgrade" | "xhttp" | "splithttp" | "http" | "h2" => {
                    if !p.path.is_empty() {
                        q.push(("path".into(), p.path.clone()));
                    }
                    if !p.host.is_empty() {
                        q.push(("host".into(), p.host.clone()));
                    }
                    if matches!(net, "xhttp" | "splithttp") && !p.mode.is_empty() {
                        q.push(("mode".into(), p.mode.clone()));
                    }
                }
                "grpc" => {
                    let svc = if !p.service_name.is_empty() {
                        p.service_name.clone()
                    } else {
                        p.path.clone()
                    };
                    if !svc.is_empty() {
                        q.push(("serviceName".into(), svc));
                    }
                    if p.multi_mode || p.mode == "multi" {
                        q.push(("mode".into(), "multi".into()));
                    } else if !p.mode.is_empty() {
                        q.push(("mode".into(), p.mode.clone()));
                    }
                    if !p.authority.is_empty() {
                        q.push(("authority".into(), p.authority.clone()));
                    }
                }
                "kcp" => {
                    if !p.header_type.is_empty() {
                        q.push(("headerType".into(), p.header_type.clone()));
                    }
                    if !p.seed.is_empty() {
                        q.push(("seed".into(), p.seed.clone()));
                    }
                }
                _ => {
                    if !p.header_type.is_empty() && p.header_type != "none" {
                        q.push(("headerType".into(), p.header_type.clone()));
                        if !p.host.is_empty() {
                            q.push(("host".into(), p.host.clone()));
                        }
                        if !p.path.is_empty() {
                            q.push(("path".into(), p.path.clone()));
                        }
                    }
                }
            }
            Some(format!(
                "vless://{}@{}:{}{}#{}",
                encode_uri_component(p.uuid.trim()),
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "vmess" => {
            if p.uuid.trim().is_empty() {
                return p.raw_uri.clone();
            }
            let net = if p.network.trim().is_empty() {
                "tcp"
            } else {
                p.network.trim()
            };
            let scy = if !p.cipher.is_empty() {
                p.cipher.as_str()
            } else if !p.security.is_empty() && p.security != "tls" && p.security != "reality" {
                p.security.as_str()
            } else {
                "auto"
            };
            let vmess_obj = json!({
                "v": "2",
                "ps": name,
                "add": p.server.trim(),
                "port": port.to_string(),
                "id": p.uuid.trim(),
                "aid": p.alter_id.unwrap_or(0).to_string(),
                "scy": scy,
                "net": net,
                "type": if p.header_type.is_empty() { "none" } else { p.header_type.as_str() },
                "host": if net == "grpc" && !p.authority.is_empty() { p.authority.as_str() } else { p.host.as_str() },
                "path": if net == "grpc" && !p.service_name.is_empty() { p.service_name.as_str() } else { p.path.as_str() },
                "tls": if p.tls || p.security == "tls" { "tls" } else { "" },
                "sni": p.sni,
                "alpn": p.alpn.join(","),
                "fp": p.fingerprint,
            });
            let b64 = STANDARD.encode(vmess_obj.to_string().as_bytes());
            Some(format!("vmess://{}", b64))
        }
        "trojan" => {
            let pass = if !p.password.is_empty() {
                p.password.trim()
            } else {
                p.uuid.trim()
            };
            if pass.is_empty() {
                return p.raw_uri.clone();
            }
            let mut q = Vec::new();
            let sec = if p.reality || p.security == "reality" {
                "reality"
            } else if p.tls || p.security == "tls" || p.security.is_empty() {
                "tls"
            } else {
                p.security.as_str()
            };
            q.push(("security".into(), sec.into()));
            let net = if p.network.is_empty() { "tcp" } else { p.network.as_str() };
            q.push(("type".into(), net.into()));
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if !p.fingerprint.is_empty() {
                q.push(("fp".into(), p.fingerprint.clone()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.join(",")));
            }
            if p.skip_cert_verify {
                q.push(("allowInsecure".into(), "1".into()));
            }
            if !p.path.is_empty() {
                q.push(("path".into(), p.path.clone()));
            }
            if !p.host.is_empty() {
                q.push(("host".into(), p.host.clone()));
            }
            if net == "grpc" && !p.service_name.is_empty() {
                q.push(("serviceName".into(), p.service_name.clone()));
            }
            if sec == "reality" {
                if !p.public_key.is_empty() {
                    q.push(("pbk".into(), p.public_key.clone()));
                }
                if !p.short_id.is_empty() {
                    q.push(("sid".into(), p.short_id.clone()));
                }
            }
            Some(format!(
                "trojan://{}@{}:{}{}#{}",
                encode_uri_component(pass),
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "shadowsocks" | "ss" => {
            let method = if !p.cipher.is_empty() {
                p.cipher.as_str()
            } else if !p.method.is_empty() {
                p.method.as_str()
            } else {
                "aes-256-gcm"
            };
            if p.password.is_empty() {
                return p.raw_uri.clone();
            }
            let creds = STANDARD.encode(format!("{}:{}", method, p.password).as_bytes());
            Some(format!("ss://{}@{}:{}#{}", creds, host, port, frag))
        }
        "ssr" => {
            let method = if !p.cipher.is_empty() {
                p.cipher.as_str()
            } else {
                "aes-256-cfb"
            };
            let ssr_proto = if p.ssr_protocol.is_empty() {
                "origin"
            } else {
                p.ssr_protocol.as_str()
            };
            let obfs = if p.obfs.is_empty() {
                "plain"
            } else {
                p.obfs.as_str()
            };
            let pass_b64 = STANDARD.encode(p.password.as_bytes()).replace('=', "");
            let mut params = Vec::new();
            if !p.obfs_param.is_empty() {
                params.push(format!(
                    "obfsparam={}",
                    STANDARD.encode(p.obfs_param.as_bytes()).replace('=', "")
                ));
            }
            if !p.protocol_param.is_empty() {
                params.push(format!(
                    "protoparam={}",
                    STANDARD.encode(p.protocol_param.as_bytes()).replace('=', "")
                ));
            }
            params.push(format!(
                "remarks={}",
                STANDARD.encode(name.as_bytes()).replace('=', "")
            ));
            let body = format!(
                "{}:{}:{}:{}:{}:{}/?{}",
                p.server.trim(),
                port,
                ssr_proto,
                method,
                obfs,
                pass_b64,
                params.join("&")
            );
            Some(format!("ssr://{}", STANDARD.encode(body.as_bytes()).replace('=', "")))
        }
        "socks5" | "socks" => {
            if !p.username.is_empty() || !p.password.is_empty() {
                let b64 = STANDARD.encode(format!("{}:{}", p.username, p.password).as_bytes());
                Some(format!("socks://{}@{}:{}#{}", b64, host, port, frag))
            } else {
                Some(format!("socks://{}:{}#{}", host, port, frag))
            }
        }
        "http" | "https" => {
            let scheme = if p.tls { "https" } else { "http" };
            if !p.username.is_empty() || !p.password.is_empty() {
                Some(format!(
                    "{}://{}:{}@{}:{}#{}",
                    scheme,
                    encode_uri_component(&p.username),
                    encode_uri_component(&p.password),
                    host,
                    port,
                    frag
                ))
            } else {
                Some(format!("{}://{}:{}#{}", scheme, host, port, frag))
            }
        }
        "hysteria2" | "hy2" => {
            let mut q = Vec::new();
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if !p.obfs.is_empty() {
                q.push(("obfs".into(), p.obfs.clone()));
            }
            if !p.obfs_password.is_empty() {
                q.push(("obfs-password".into(), p.obfs_password.clone()));
            }
            if let Some(ref mport) = p.ports {
                if !mport.is_empty() {
                    q.push(("mport".into(), mport.clone()));
                }
            }
            if p.skip_cert_verify {
                q.push(("insecure".into(), "1".into()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.join(",")));
            }
            Some(format!(
                "hysteria2://{}@{}:{}{}#{}",
                encode_uri_component(&p.password),
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "hysteria" | "hy" => {
            let mut q = Vec::new();
            q.push(("protocol".into(), if p.network.is_empty() { "udp".into() } else { p.network.clone() }));
            let auth = if !p.auth_str.is_empty() {
                &p.auth_str
            } else {
                &p.password
            };
            if !auth.is_empty() {
                q.push(("auth".into(), auth.clone()));
            }
            if !p.sni.is_empty() {
                q.push(("peer".into(), p.sni.clone()));
            }
            if let Some(ref up) = p.up {
                q.push(("upmbps".into(), up.clone()));
            }
            if let Some(ref down) = p.down {
                q.push(("downmbps".into(), down.clone()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.join(",")));
            }
            if !p.obfs.is_empty() {
                q.push(("obfs".into(), p.obfs.clone()));
            }
            if !p.obfs_param.is_empty() {
                q.push(("obfsParam".into(), p.obfs_param.clone()));
            }
            if p.skip_cert_verify {
                q.push(("insecure".into(), "1".into()));
            }
            Some(format!(
                "hysteria://{}:{}{}#{}",
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "tuic" => {
            let mut q = Vec::new();
            if let Some(ref cc) = p.congestion_control {
                if !cc.is_empty() {
                    q.push(("congestion_control".into(), cc.clone()));
                }
            }
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.join(",")));
            }
            if let Some(ref udp_m) = p.udp_relay_mode {
                if !udp_m.is_empty() {
                    q.push(("udp_relay_mode".into(), udp_m.clone()));
                }
            }
            if p.skip_cert_verify {
                q.push(("allow_insecure".into(), "1".into()));
            }
            let auth = if !p.password.is_empty() {
                format!("{}:{}", encode_uri_component(&p.uuid), encode_uri_component(&p.password))
            } else {
                encode_uri_component(&p.uuid)
            };
            Some(format!(
                "tuic://{}@{}:{}{}#{}",
                auth,
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "anytls" => {
            let mut q = Vec::new();
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if !p.fingerprint.is_empty() {
                q.push(("fp".into(), p.fingerprint.clone()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.join(",")));
            }
            if p.skip_cert_verify {
                q.push(("insecure".into(), "1".into()));
            }
            Some(format!(
                "anytls://{}@{}:{}{}#{}",
                encode_uri_component(&p.password),
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "naive" | "naive+https" => {
            let mut q = Vec::new();
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            let auth = if !p.password.is_empty() {
                format!(
                    "{}:{}",
                    encode_uri_component(&p.username),
                    encode_uri_component(&p.password)
                )
            } else {
                encode_uri_component(&p.username)
            };
            Some(format!(
                "naive+https://{}@{}:{}{}#{}",
                auth,
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "wireguard" | "wg" => {
            if p.private_key.is_empty() {
                return p.raw_uri.clone();
            }
            let mut q = Vec::new();
            if !p.local_address.is_empty() {
                q.push(("address".into(), p.local_address.clone()));
            }
            let wg_peer_pub = if !p.peer_public_key.is_empty() {
                &p.peer_public_key
            } else {
                &p.public_key
            };
            if !wg_peer_pub.is_empty() {
                q.push(("publickey".into(), wg_peer_pub.clone()));
            }
            if !p.preshared_key.is_empty() {
                q.push(("presharedkey".into(), p.preshared_key.clone()));
            }
            if let Some(mtu) = p.mtu {
                q.push(("mtu".into(), mtu.to_string()));
            }
            if let Some(ref res) = p.reserved {
                if !res.is_empty() {
                    let s: Vec<String> = res.iter().map(|n| n.to_string()).collect();
                    q.push(("reserved".into(), s.join(",")));
                }
            }
            Some(format!(
                "wireguard://{}@{}:{}{}#{}",
                encode_uri_component(&p.private_key),
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "masque" => {
            if let Some(ref raw) = p.raw_uri {
                if raw.starts_with("masque://") {
                    return Some(raw.clone());
                }
            }
            let mut q = Vec::new();
            if !p.private_key.is_empty() {
                q.push(("privateKey".into(), p.private_key.clone()));
            }
            if !p.public_key.is_empty() {
                q.push(("publicKey".into(), p.public_key.clone()));
            } else if !p.peer_public_key.is_empty() {
                q.push(("publicKey".into(), p.peer_public_key.clone()));
            }
            if !p.local_address.is_empty() {
                q.push(("address".into(), p.local_address.clone()));
            }
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            Some(format!(
                "masque://{}:{}{}#{}",
                host,
                port,
                append_query_pairs(&q),
                frag
            ))
        }
        "ssh" => {
            let user = if p.username.is_empty() {
                "root"
            } else {
                p.username.as_str()
            };
            let auth = if !p.password.is_empty() {
                format!("{}:{}", encode_uri_component(user), encode_uri_component(&p.password))
            } else {
                encode_uri_component(user)
            };
            Some(format!("ssh://{}@{}:{}#{}", auth, host, port, frag))
        }
        _ => p.raw_uri.clone(),
    }
}

pub fn build_xray_links(
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

    let mut links = Vec::new();
    for (i, p) in profiles.iter().enumerate() {
        let mut p_copy = p.clone();
        p_copy.name = remove_control_chars(&p.name);
        if p_copy.name.is_empty() {
            p_copy.name = format!("Proxy-{}", i + 1);
        }
        if let Some(uri) = profile_to_xray_uri(&p_copy) {
            if !uri.trim().is_empty() {
                links.push(uri);
            }
        }
    }
    links.join("\n")
}

pub fn build_xray_base64(xray_links_text: &str) -> String {
    if xray_links_text.trim().is_empty() {
        return String::new();
    }
    STANDARD.encode(xray_links_text.trim().as_bytes())
}

pub fn convert_profile_to_xray_outbound(p: &ProxyProfile, tag: &str) -> Option<Value> {
    let proto = p.protocol.to_lowercase();
    let net = if p.network.is_empty() {
        "tcp"
    } else {
        p.network.as_str()
    };

    let stream = || -> Value {
        let mut st = Map::new();
        st.insert("network".into(), Value::String(net.into()));
        let sec = if p.reality || p.security == "reality" {
            "reality"
        } else if p.tls || p.security == "tls" {
            "tls"
        } else {
            "none"
        };
        st.insert("security".into(), Value::String(sec.into()));
        if sec == "tls" {
            let mut tls_obj = Map::new();
            tls_obj.insert(
                "serverName".into(),
                Value::String(if !p.sni.is_empty() {
                    p.sni.clone()
                } else {
                    p.server.clone()
                }),
            );
            tls_obj.insert("allowInsecure".into(), Value::Bool(p.skip_cert_verify));
            if !p.fingerprint.is_empty() {
                tls_obj.insert("fingerprint".into(), Value::String(p.fingerprint.clone()));
            }
            if !p.alpn.is_empty() {
                tls_obj.insert("alpn".into(), json!(p.alpn));
            }
            st.insert("tlsSettings".into(), Value::Object(tls_obj));
        } else if sec == "reality" {
            let mut rel = Map::new();
            rel.insert(
                "serverName".into(),
                Value::String(if !p.sni.is_empty() {
                    p.sni.clone()
                } else {
                    p.server.clone()
                }),
            );
            rel.insert(
                "fingerprint".into(),
                Value::String(if p.fingerprint.is_empty() {
                    "chrome".into()
                } else {
                    p.fingerprint.clone()
                }),
            );
            rel.insert("publicKey".into(), Value::String(p.public_key.clone()));
            rel.insert("shortId".into(), Value::String(p.short_id.clone()));
            if !p.spider_x.is_empty() {
                rel.insert("spiderX".into(), Value::String(p.spider_x.clone()));
            }
            st.insert("realitySettings".into(), Value::Object(rel));
        }
        match net {
            "ws" => {
                let mut ws = Map::new();
                ws.insert(
                    "path".into(),
                    Value::String(if p.path.is_empty() { "/".into() } else { p.path.clone() }),
                );
                if !p.host.is_empty() {
                    ws.insert("headers".into(), json!({ "Host": p.host }));
                }
                st.insert("wsSettings".into(), Value::Object(ws));
            }
            "grpc" => {
                st.insert(
                    "grpcSettings".into(),
                    json!({
                        "serviceName": if !p.service_name.is_empty() { &p.service_name } else { &p.path },
                        "multiMode": p.multi_mode || p.mode == "multi"
                    }),
                );
            }
            _ => {}
        }
        Value::Object(st)
    };

    match proto.as_str() {
        "vless" => Some(json!({
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": p.server,
                    "port": p.server_port,
                    "users": [{
                        "id": p.uuid,
                        "encryption": if p.encryption.is_empty() { "none" } else { p.encryption.as_str() },
                        "flow": p.flow
                    }]
                }]
            },
            "streamSettings": stream()
        })),
        "vmess" => Some(json!({
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": p.server,
                    "port": p.server_port,
                    "users": [{
                        "id": p.uuid,
                        "alterId": p.alter_id.unwrap_or(0),
                        "security": if p.cipher.is_empty() { "auto" } else { p.cipher.as_str() }
                    }]
                }]
            },
            "streamSettings": stream()
        })),
        "trojan" => Some(json!({
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": p.server,
                    "port": p.server_port,
                    "password": if !p.password.is_empty() { p.password.as_str() } else { p.uuid.as_str() }
                }]
            },
            "streamSettings": stream()
        })),
        "shadowsocks" | "ss" => Some(json!({
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": p.server,
                    "port": p.server_port,
                    "method": if !p.cipher.is_empty() { p.cipher.as_str() } else { "aes-256-gcm" },
                    "password": p.password
                }]
            }
        })),
        _ => None,
    }
}
