use crate::http_client::fetch_text_with_fallback;
use crate::models::{AmneziaWgOptions, DecryptionError, ProxyMode, ProxyProfile};
use serde_json::{Map, Value};

fn parse_yaml_value(raw: &str) -> Value {
    let s = raw.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return Value::String(s[1..s.len() - 1].to_string());
    }
    if s == "true" {
        return Value::Bool(true);
    }
    if s == "false" {
        return Value::Bool(false);
    }
    if let Ok(i) = s.parse::<i64>() {
        return Value::Number(i.into());
    }
    if let Ok(f) = s.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(f) {
            return Value::Number(num);
        }
    }
    if s.starts_with('[') && s.ends_with(']') {
        let json_like = s.replace('\'', "\"");
        if let Ok(v) = serde_json::from_str::<Value>(&json_like) {
            return v;
        }
        let items: Vec<Value> = s[1..s.len() - 1]
            .split(',')
            .map(|part| {
                part.trim()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_string()
            })
            .filter(|x| !x.is_empty())
            .map(|x| {
                if let Ok(n) = x.parse::<i64>() {
                    Value::Number(n.into())
                } else {
                    Value::String(x)
                }
            })
            .collect();
        return Value::Array(items);
    }
    Value::String(s.to_string())
}

fn parse_flow_mapping(rest: &str) -> Option<Map<String, Value>> {
    if !rest.starts_with('{') || !rest.ends_with('}') {
        return None;
    }
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(rest) {
        return Some(m);
    }
    // Pseudo-JSON Clash flow line: { name: 'A', type: vless, port: 443, ws-opts: { path: /ws } }
    let inner = &rest[1..rest.len() - 1];
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_quote: Option<char> = None;
    let mut start = 0;
    for (idx, ch) in inner.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&inner[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);

    let mut out = Map::new();
    for part in parts {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((k, v)) = p.split_once(':') {
            let clean_k = k.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
            let v_tr = v.trim();
            if v_tr.starts_with('{') && v_tr.ends_with('}') {
                if let Some(sub) = parse_flow_mapping(v_tr) {
                    out.insert(clean_k, Value::Object(sub));
                    continue;
                }
            }
            out.insert(clean_k, parse_yaml_value(v_tr));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

pub fn extract_proxy_provider_urls(yaml_text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut in_providers = false;
    for line in yaml_text.lines() {
        let t = line.trim();
        if t.starts_with("proxy-providers:") && !line.starts_with(' ') && !line.starts_with('\t') {
            in_providers = true;
            continue;
        }
        if in_providers
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && t.contains(':')
            && !t.starts_with('#')
        {
            in_providers = false;
            continue;
        }
        if in_providers {
            if let Some(idx) = t.find("url:") {
                let val = t[idx + 4..]
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_string();
                if val.starts_with("http://") || val.starts_with("https://") {
                    urls.push(val);
                }
            }
        }
    }
    urls
}

fn s_val(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub fn clash_object_to_profile(p: &Map<String, Value>) -> ProxyProfile {
    let mut typ = s_val(p.get("type")).to_lowercase();
    let reality = p.get("reality-opts").and_then(|v| v.as_object());

    if typ.is_empty() || matches!(typ.as_str(), "proxy" | "generic" | "custom") {
        if reality.and_then(|r| r.get("public-key")).is_some()
            || p.contains_key("flow")
            || p.contains_key("uuid")
        {
            typ = "vless".to_string();
        } else if p.contains_key("alterId") {
            typ = "vmess".to_string();
        } else if p.contains_key("cipher") {
            typ = "ss".to_string();
        } else if p.contains_key("password") {
            typ = "trojan".to_string();
        } else {
            typ = "vless".to_string();
        }
    }

    let ws = p.get("ws-opts").and_then(|v| v.as_object());
    let grpc = p.get("grpc-opts").and_then(|v| v.as_object());
    let h2 = p.get("h2-opts").and_then(|v| v.as_object());
    let xhttp = p.get("xhttp-opts").and_then(|v| v.as_object());

    let mut network = s_val(p.get("network")).to_lowercase();
    if network.is_empty() {
        network = if ws.is_some() {
            "ws".to_string()
        } else if grpc.is_some() {
            "grpc".to_string()
        } else {
            "tcp".to_string()
        };
    }
    if ws.and_then(|w| w.get("v2ray-http-upgrade")).and_then(|v| v.as_bool()) == Some(true) {
        network = "httpupgrade".to_string();
    }

    let server = {
        let s = s_val(p.get("server"));
        if s.is_empty() { "127.0.0.1".to_string() } else { s }
    };
    let port = p
        .get("port")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(443) as u16;
    let tls = p.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let has_reality = reality
        .and_then(|r| r.get("public-key"))
        .map(|v| !s_val(Some(v)).is_empty())
        .unwrap_or(false);

    let ws_host = ws
        .and_then(|w| w.get("headers"))
        .and_then(|h| h.get("Host"))
        .or_else(|| h2.and_then(|h| h.get("host")).and_then(|v| v.as_array()?.first()))
        .or_else(|| h2.and_then(|h| h.get("host")))
        .or_else(|| xhttp.and_then(|x| x.get("host")))
        .or_else(|| p.get("servername"))
        .map(|v| s_val(Some(v)))
        .unwrap_or_default();

    let path = ws
        .and_then(|w| w.get("path"))
        .or_else(|| xhttp.and_then(|x| x.get("path")))
        .or_else(|| h2.and_then(|h| h.get("path")))
        .map(|v| s_val(Some(v)))
        .unwrap_or_default();

    let sni = s_val(p.get("servername").or_else(|| p.get("sni")));
    let proto = if typ == "ss" {
        "shadowsocks".to_string()
    } else if typ == "ssr" {
        "shadowsocksr".to_string()
    } else {
        typ.clone()
    };

    let name = {
        let n = s_val(p.get("name"));
        if n.is_empty() {
            format!("{}-{}", proto.to_uppercase(), server)
        } else {
            n
        }
    };

    let alpn = p
        .get("alpn")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let reserved = p.get("reserved").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_i64().map(|n| n as i32))
            .collect::<Vec<_>>()
    });

    let amnezia_options = p.get("amnezia-wg-option").and_then(|v| v.as_object()).map(|a| {
        let num = |k: &str| a.get(k).and_then(|x| x.as_i64());
        AmneziaWgOptions {
            jc: num("jc"),
            jmin: num("jmin"),
            jmax: num("jmax"),
            s1: num("s1"),
            s2: num("s2"),
            s3: num("s3"),
            s4: num("s4"),
            h1: a.get("h1").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
            h2: a.get("h2").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
            h3: a.get("h3").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
            h4: a.get("h4").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
            ..Default::default()
        }
    });

    let host_key = p
        .get("host-key")
        .map(|v| match v {
            Value::Array(arr) => arr.iter().map(|x| s_val(Some(x))).collect(),
            Value::String(s) => vec![s.clone()],
            _ => Vec::new(),
        })
        .unwrap_or_default();

    ProxyProfile {
        name,
        protocol: proto,
        server,
        server_port: port,
        uuid: s_val(p.get("uuid").or_else(|| p.get("password"))),
        password: s_val(p.get("password").or_else(|| p.get("uuid"))),
        username: s_val(p.get("username")),
        psk: s_val(p.get("psk")),
        auth_str: s_val(p.get("auth_str").or_else(|| p.get("auth").or_else(|| p.get("password")))),
        flow: s_val(p.get("flow")),
        encryption: {
            let e = s_val(p.get("encryption"));
            if e.is_empty() { "none".to_string() } else { e }
        },
        alter_id: p.get("alterId").and_then(|v| v.as_u64()).map(|n| n as u32),
        network,
        path,
        host: ws_host,
        mode: xhttp.and_then(|x| x.get("mode")).map(|v| s_val(Some(v))).unwrap_or_default(),
        service_name: grpc
            .and_then(|g| g.get("grpc-service-name"))
            .map(|v| s_val(Some(v)))
            .unwrap_or_default(),
        security: if has_reality {
            "reality".to_string()
        } else if tls {
            "tls".to_string()
        } else {
            "none".to_string()
        },
        tls,
        reality: has_reality,
        sni,
        fingerprint: {
            let fp = s_val(p.get("client-fingerprint"));
            if fp.is_empty() { "chrome".to_string() } else { fp }
        },
        public_key: {
            let pk = reality
                .and_then(|r| r.get("public-key"))
                .or_else(|| p.get("public-key"))
                .or_else(|| p.get("publicKey"));
            s_val(pk)
        },
        short_id: reality
            .and_then(|r| r.get("short-id"))
            .map(|v| s_val(Some(v)))
            .unwrap_or_default(),
        spider_x: reality
            .and_then(|r| r.get("spider-x"))
            .map(|v| s_val(Some(v)))
            .unwrap_or_default(),
        alpn,
        skip_cert_verify: p.get("skip-cert-verify").and_then(|v| v.as_bool()).unwrap_or(false),
        method: s_val(p.get("cipher")),
        cipher: s_val(p.get("cipher")),
        ssr_protocol: s_val(p.get("protocol")),
        protocol_param: s_val(p.get("protocol-param")),
        obfs: s_val(p.get("obfs")),
        obfs_password: s_val(p.get("obfs-password")),
        obfs_param: s_val(p.get("obfs-param")),
        ports: p.get("ports").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        hop_interval: p.get("hop-interval").and_then(|v| v.as_u64()),
        congestion_control: p.get("congestion-controller").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        udp_relay_mode: p.get("udp-relay-mode").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        private_key: s_val(p.get("private-key").or_else(|| p.get("privateKey"))),
        peer_public_key: s_val(
            p.get("peer-public-key")
                .or_else(|| p.get("public-key"))
                .or_else(|| p.get("publicKey")),
        ),
        local_address: s_val(p.get("ip")),
        ipv6: p.get("ipv6").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        mtu: p.get("mtu").and_then(|v| v.as_u64()).map(|n| n as u32),
        keepalive: p.get("persistent-keepalive").and_then(|v| v.as_u64()).map(|n| n as u32),
        reserved,
        amnezia_options,
        ca: p.get("ca").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        cert: p.get("certificate").map(|v| s_val(Some(v))).filter(|x| !x.is_empty()),
        key: if p.contains_key("certificate") {
            p.get("private-key").map(|v| s_val(Some(v))).filter(|x| !x.is_empty())
        } else {
            None
        },
        host_key,
        udp: p.get("udp").and_then(|v| v.as_bool()),
        remote_dns_resolve: p.get("remote-dns-resolve").and_then(|v| v.as_bool()),
        dns: p
            .get("dns")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub fn parse_mihomo_yaml(raw_text: &str) -> Result<(Vec<ProxyProfile>, Vec<String>), DecryptionError> {
    let lines: Vec<&str> = raw_text.lines().collect();
    let mut proxies: Vec<Map<String, Value>> = Vec::new();
    let mut in_proxies = false;
    let mut current_proxy: Option<Map<String, Value>> = None;
    let mut current_sub_key: Option<String> = None;
    let mut current_sub_sub_key: Option<String> = None;
    let mut proxies_indent = 0usize;

    let has_proxies_header = lines
        .iter()
        .any(|l| l.trim_start().to_lowercase().starts_with("proxies:") && !l.starts_with(' ') && !l.starts_with('\t'));
    if !has_proxies_header {
        let starts_list = lines.iter().any(|l| {
            let t = l.trim_start();
            t.starts_with("- name:")
                || t.starts_with("- type:")
                || t.starts_with("- server:")
                || t.starts_with("- {")
        });
        if starts_list {
            in_proxies = true;
        }
    }

    for raw_line in lines {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let no_leading_ws = !raw_line.starts_with(' ') && !raw_line.starts_with('\t');
        if no_leading_ws && trimmed.to_lowercase().starts_with("proxies:") {
            in_proxies = true;
            continue;
        }
        if in_proxies && no_leading_ws && trimmed.contains(':') && !trimmed.starts_with('-') {
            in_proxies = false;
            if let Some(cp) = current_proxy.take() {
                proxies.push(cp);
            }
            continue;
        }
        if !in_proxies {
            continue;
        }

        let leading_ws = raw_line.len() - raw_line.trim_start().len();
        let after_ws = &raw_line[leading_ws..];
        if after_ws.starts_with('-') && (after_ws.len() == 1 || after_ws.as_bytes()[1].is_ascii_whitespace()) {
            let rest = after_ws[1..].trim();
            if proxies_indent == 0 {
                proxies_indent = leading_ws;
            }
            if leading_ws > proxies_indent {
                if let (Some(cp), Some(sub_k)) = (current_proxy.as_mut(), current_sub_key.as_ref()) {
                    let arr = cp
                        .entry(sub_k.clone())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if !arr.is_array() {
                        *arr = Value::Array(Vec::new());
                    }
                    if let Some(a) = arr.as_array_mut() {
                        a.push(parse_yaml_value(rest));
                    }
                }
                continue;
            }

            if let Some(cp) = current_proxy.take() {
                proxies.push(cp);
            }
            let mut new_map = Map::new();
            current_sub_key = None;
            current_sub_sub_key = None;

            if rest.starts_with('{') && rest.ends_with('}') {
                if let Some(flow) = parse_flow_mapping(rest) {
                    new_map.extend(flow);
                }
            } else if let Some((k, v)) = rest.split_once(':') {
                new_map.insert(k.trim().to_string(), parse_yaml_value(v));
            }
            current_proxy = Some(new_map);
            continue;
        }

        if let Some(cp) = current_proxy.as_mut() {
            if let Some((k_raw, v_raw)) = trimmed.split_once(':') {
                let key = k_raw.trim().to_string();
                let val = v_raw.trim();
                if leading_ws > proxies_indent + 4 {
                    if let (Some(sub_k), Some(sub_sub_k)) = (current_sub_key.as_ref(), current_sub_sub_key.as_ref()) {
                        let parent = cp.entry(sub_k.clone()).or_insert_with(|| Value::Object(Map::new()));
                        if let Some(pm) = parent.as_object_mut() {
                            let child = pm.entry(sub_sub_k.clone()).or_insert_with(|| Value::Object(Map::new()));
                            if let Some(cm) = child.as_object_mut() {
                                cm.insert(key, parse_yaml_value(val));
                            }
                        }
                    }
                } else if leading_ws > proxies_indent + 2 && current_sub_key.is_some() {
                    let sub_k = current_sub_key.as_ref().unwrap().clone();
                    if val.is_empty() {
                        current_sub_sub_key = Some(key.clone());
                        let parent = cp.entry(sub_k).or_insert_with(|| Value::Object(Map::new()));
                        if let Some(pm) = parent.as_object_mut() {
                            pm.insert(key, Value::Object(Map::new()));
                        }
                    } else {
                        current_sub_sub_key = None;
                        let parent = cp.entry(sub_k).or_insert_with(|| Value::Object(Map::new()));
                        if let Some(pm) = parent.as_object_mut() {
                            pm.insert(key, parse_yaml_value(val));
                        }
                    }
                } else if val.is_empty() {
                    current_sub_key = Some(key.clone());
                    current_sub_sub_key = None;
                    cp.insert(key, Value::Object(Map::new()));
                } else {
                    current_sub_key = None;
                    current_sub_sub_key = None;
                    cp.insert(key, parse_yaml_value(val));
                }
            }
        }
    }

    if let Some(cp) = current_proxy {
        proxies.push(cp);
    }

    let provider_urls = extract_proxy_provider_urls(raw_text);
    if proxies.is_empty() && provider_urls.is_empty() {
        return Err(DecryptionError::plain(
            "هیچ پروکسی معتبری در بخش proxies یا proxy-providers فایل YAML یافت نشد.",
        ));
    }

    let profiles = proxies
        .iter()
        .filter(|p| {
            let typ = s_val(p.get("type")).to_lowercase();
            !matches!(
                typ.trim(),
                "direct" | "reject" | "reject-drop" | "pass" | "compatible"
            )
        })
        .map(clash_object_to_profile)
        .collect();
    Ok((profiles, provider_urls))
}

pub async fn parse_mihomo_yaml_async(
    raw_text: &str,
    proxy_mode: &ProxyMode,
    custom_proxy_url: &str,
) -> Result<Vec<ProxyProfile>, DecryptionError> {
    let (mut profiles, provider_urls) = parse_mihomo_yaml(raw_text)?;
    if !provider_urls.is_empty() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let mut set = tokio::task::JoinSet::new();
        let mut seen_urls = std::collections::HashSet::new();
        let pmode = proxy_mode.clone();
        let cproxy = custom_proxy_url.to_string();

        for p_url in provider_urls {
            if seen_urls.len() >= 10 {
                break;
            }
            if !seen_urls.insert(p_url.clone()) {
                continue;
            }
            let sem_c = sem.clone();
            let pm = pmode.clone();
            let cp = cproxy.clone();
            set.spawn(async move {
                let Ok(_permit) = sem_c.acquire_owned().await else {
                    return None;
                };
                fetch_text_with_fallback(&p_url, &pm, &cp, 6).await.ok()
            });
        }

        let mut fetched_bodies = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(12), async {
            while let Some(res) = set.join_next().await {
                if let Ok(Some(sub_txt)) = res {
                    fetched_bodies.push(sub_txt);
                }
            }
        })
        .await;

        for sub_txt in fetched_bodies {
            if let Ok((sub_profiles, _)) = parse_mihomo_yaml(&sub_txt) {
                profiles.extend(sub_profiles);
            } else if let Ok(parsed) = Box::pin(
                crate::parsers::subscription::parse_subscription_text(
                    &sub_txt,
                    proxy_mode,
                    custom_proxy_url,
                ),
            )
            .await
            {
                profiles.extend(parsed.profiles);
            }
        }
    }
    Ok(profiles)
}
