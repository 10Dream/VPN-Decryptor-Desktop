use crate::models::ProxyProfile;
use crate::parsers::subscription::is_dns_protocol;
use crate::sanitizer::{
    clean_proxy_name, filter_and_deduplicate_with_stats, is_valid_curve25519_key,
    normalize_ec_private_key, remove_control_chars, DEFAULT_MASQUE_WARP_PUBKEY,
};
use regex::Regex;
use std::collections::HashSet;

static HEADER_BLOCK: &str = include_str!("../../assets/mihomo_header.txt");
static GROUPS_TEMPLATE: &str = include_str!("../../assets/mihomo_groups.txt");
static RULES_BLOCK: &str = include_str!("../../assets/mihomo_rules.txt");

fn ystr(s: &str) -> String {
    let cleaned = remove_control_chars(s);
    serde_json::to_string(&cleaned).unwrap_or_else(|_| "\"\"".to_string())
}

fn push_kv(lines: &mut Vec<String>, key: &str, val: &str) {
    lines.push(format!("    {}: {}", key, val));
}

fn format_string_list(lines: &mut Vec<String>, key: &str, items: &[String], indent: usize) {
    if items.is_empty() {
        return;
    }
    let pad = " ".repeat(indent);
    lines.push(format!("{}{}:", pad, key));
    for item in items {
        lines.push(format!("{}  - {}", pad, ystr(item)));
    }
}

pub fn format_proxy_yaml(p: &ProxyProfile) -> Option<String> {
    if p.is_dns_tunnel || is_dns_protocol(&p.protocol) {
        return None;
    }
    let raw_proto = p.protocol.to_lowercase();
    let proto = raw_proto.trim();
    if p.server.trim().is_empty() && proto != "tailscale" && proto != "easytier" {
        return None;
    }

    let name = clean_proxy_name(&p.name, "Proxy");
    let mut lines = vec![format!("  - name: {}", ystr(&name))];

    match proto {
        "vless" | "vmess" | "trojan" => {
            let mtype = proto;
            push_kv(&mut lines, "type", mtype);
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &if p.server_port == 0 { 443 } else { p.server_port }.to_string());

            if mtype == "vless" || mtype == "vmess" {
                if p.uuid.trim().is_empty() {
                    return None;
                }
                push_kv(&mut lines, "uuid", &ystr(p.uuid.trim()));
                if mtype == "vmess" {
                    push_kv(&mut lines, "alterId", &p.alter_id.unwrap_or(0).to_string());
                    let c = if p.cipher.is_empty() { "auto" } else { p.cipher.as_str() };
                    push_kv(&mut lines, "cipher", &ystr(c));
                } else {
                    if !p.flow.is_empty() {
                        push_kv(&mut lines, "flow", &ystr(&p.flow));
                    }
                    if !p.encryption.is_empty() && p.encryption != "none" {
                        push_kv(&mut lines, "encryption", &ystr(&p.encryption));
                    }
                }
            } else {
                let pass = if !p.password.is_empty() { p.password.trim() } else { p.uuid.trim() };
                if pass.is_empty() {
                    return None;
                }
                push_kv(&mut lines, "password", &ystr(pass));
            }

            push_kv(&mut lines, "udp", "true");

            let is_reality = p.reality || p.security == "reality";
            let is_tls = p.tls || p.security == "tls" || is_reality || mtype == "trojan";
            if is_tls {
                push_kv(&mut lines, "tls", "true");
                let servername = if !p.sni.is_empty() { p.sni.as_str() } else { p.server.as_str() };
                if mtype == "trojan" {
                    push_kv(&mut lines, "sni", &ystr(servername));
                } else {
                    push_kv(&mut lines, "servername", &ystr(servername));
                }
                if p.skip_cert_verify && !is_reality {
                    push_kv(&mut lines, "skip-cert-verify", "true");
                }
                if !p.fingerprint.is_empty() {
                    push_kv(&mut lines, "client-fingerprint", &ystr(&p.fingerprint));
                } else if is_reality {
                    push_kv(&mut lines, "client-fingerprint", "\"chrome\"");
                }
                if !p.alpn.is_empty() {
                    format_string_list(&mut lines, "alpn", &p.alpn, 4);
                }
            }

            if is_reality && !p.public_key.is_empty() {
                lines.push("    reality-opts:".to_string());
                lines.push(format!("      public-key: {}", ystr(&p.public_key)));
                if !p.short_id.is_empty() {
                    lines.push(format!("      short-id: {}", ystr(&p.short_id)));
                }
            }

            let net = if p.network.is_empty() { "tcp" } else { p.network.trim() };
            match net {
                "ws" => {
                    push_kv(&mut lines, "network", "ws");
                    lines.push("    ws-opts:".to_string());
                    let path = if p.path.is_empty() { "/" } else { p.path.as_str() };
                    lines.push(format!("      path: {}", ystr(path)));
                    let host_hdr = if !p.host.is_empty() { p.host.as_str() } else { p.sni.as_str() };
                    if !host_hdr.is_empty() {
                        lines.push("      headers:".to_string());
                        lines.push(format!("        Host: {}", ystr(host_hdr)));
                    }
                }
                "httpupgrade" => {
                    push_kv(&mut lines, "network", "ws");
                    lines.push("    ws-opts:".to_string());
                    let path = if p.path.is_empty() { "/" } else { p.path.as_str() };
                    lines.push(format!("      path: {}", ystr(path)));
                    lines.push("      v2ray-http-upgrade: true".to_string());
                    let host_hdr = if !p.host.is_empty() { p.host.as_str() } else { p.sni.as_str() };
                    if !host_hdr.is_empty() {
                        lines.push("      headers:".to_string());
                        lines.push(format!("        Host: {}", ystr(host_hdr)));
                    }
                }
                "xhttp" | "splithttp" => {
                    push_kv(&mut lines, "network", "xhttp");
                    lines.push("    xhttp-opts:".to_string());
                    let path = if p.path.is_empty() { "/" } else { p.path.as_str() };
                    lines.push(format!("      path: {}", ystr(path)));
                    let host_val = if !p.host.is_empty() { p.host.as_str() } else { p.sni.as_str() };
                    if !host_val.is_empty() {
                        lines.push(format!("      host: {}", ystr(host_val)));
                    }
                    if !p.mode.is_empty() {
                        lines.push(format!("      mode: {}", ystr(&p.mode)));
                    }
                }
                "grpc" => {
                    push_kv(&mut lines, "network", "grpc");
                    let svc = if !p.service_name.is_empty() { p.service_name.as_str() } else { p.path.as_str() };
                    if !svc.is_empty() {
                        lines.push("    grpc-opts:".to_string());
                        lines.push(format!("      grpc-service-name: {}", ystr(svc)));
                    }
                }
                "h2" | "http" => {
                    push_kv(&mut lines, "network", if net == "h2" { "h2" } else { "http" });
                    if !p.path.is_empty() || !p.host.is_empty() {
                        lines.push(format!("    {}-opts:", if net == "h2" { "h2" } else { "http" }));
                        if !p.path.is_empty() {
                            lines.push(format!("      path: {}", ystr(&p.path)));
                        }
                        if !p.host.is_empty() {
                            lines.push("      host:".to_string());
                            lines.push(format!("        - {}", ystr(&p.host)));
                        }
                    }
                }
                _ => {
                    push_kv(&mut lines, "network", "tcp");
                }
            }
        }
        "shadowsocks" | "ss" => {
            let cipher = if !p.cipher.is_empty() {
                p.cipher.as_str()
            } else if !p.method.is_empty() {
                p.method.as_str()
            } else {
                "aes-256-gcm"
            };
            if p.password.is_empty() {
                return None;
            }
            push_kv(&mut lines, "type", "ss");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "cipher", &ystr(cipher));
            push_kv(&mut lines, "password", &ystr(&p.password));
            push_kv(&mut lines, "udp", "true");
            if !p.obfs.is_empty() && !p.obfs.eq_ignore_ascii_case("plain") {
                push_kv(&mut lines, "plugin", "\"obfs\"");
                lines.push("    plugin-opts:".to_string());
                lines.push(format!("      mode: {}", ystr(&p.obfs)));
                if !p.host.is_empty() {
                    lines.push(format!("      host: {}", ystr(&p.host)));
                }
            }
        }
        "ssr" => {
            if p.password.is_empty() {
                return None;
            }
            push_kv(&mut lines, "type", "ssr");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "cipher", &ystr(if p.cipher.is_empty() { "aes-256-cfb" } else { p.cipher.as_str() }));
            push_kv(&mut lines, "password", &ystr(&p.password));
            push_kv(&mut lines, "obfs", &ystr(if p.obfs.is_empty() { "plain" } else { p.obfs.as_str() }));
            push_kv(&mut lines, "protocol", &ystr(if p.ssr_protocol.is_empty() { "origin" } else { p.ssr_protocol.as_str() }));
            if !p.obfs_param.is_empty() {
                push_kv(&mut lines, "obfs-param", &ystr(&p.obfs_param));
            }
            if !p.protocol_param.is_empty() {
                push_kv(&mut lines, "protocol-param", &ystr(&p.protocol_param));
            }
            push_kv(&mut lines, "udp", "true");
        }
        "socks5" | "socks" => {
            push_kv(&mut lines, "type", "socks5");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            if !p.username.is_empty() {
                push_kv(&mut lines, "username", &ystr(&p.username));
            }
            if !p.password.is_empty() {
                push_kv(&mut lines, "password", &ystr(&p.password));
            }
            if p.tls {
                push_kv(&mut lines, "tls", "true");
                if p.skip_cert_verify {
                    push_kv(&mut lines, "skip-cert-verify", "true");
                }
            }
            push_kv(&mut lines, "udp", "true");
        }
        "http" | "https" => {
            push_kv(&mut lines, "type", "http");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            if !p.username.is_empty() {
                push_kv(&mut lines, "username", &ystr(&p.username));
            }
            if !p.password.is_empty() {
                push_kv(&mut lines, "password", &ystr(&p.password));
            }
            if p.tls || proto == "https" {
                push_kv(&mut lines, "tls", "true");
                if !p.sni.is_empty() {
                    push_kv(&mut lines, "sni", &ystr(&p.sni));
                }
                if p.skip_cert_verify {
                    push_kv(&mut lines, "skip-cert-verify", "true");
                }
            }
        }
        "hysteria2" | "hy2" => {
            push_kv(&mut lines, "type", "hysteria2");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "password", &ystr(&p.password));
            if let Some(ref ports) = p.ports {
                if !ports.is_empty() {
                    push_kv(&mut lines, "ports", &ystr(ports));
                }
            }
            if let Some(hop) = p.hop_interval {
                push_kv(&mut lines, "hop-interval", &hop.to_string());
            }
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
            if p.skip_cert_verify {
                push_kv(&mut lines, "skip-cert-verify", "true");
            }
            if !p.obfs.is_empty() && !p.obfs_password.is_empty() {
                push_kv(&mut lines, "obfs", &ystr(&p.obfs));
                push_kv(&mut lines, "obfs-password", &ystr(&p.obfs_password));
            }
            if let Some(ref up) = p.up {
                if !up.is_empty() {
                    push_kv(&mut lines, "up", &ystr(up));
                }
            }
            if let Some(ref down) = p.down {
                if !down.is_empty() {
                    push_kv(&mut lines, "down", &ystr(down));
                }
            }
            if !p.alpn.is_empty() {
                format_string_list(&mut lines, "alpn", &p.alpn, 4);
            }
        }
        "hysteria" | "hy" => {
            push_kv(&mut lines, "type", "hysteria");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            let auth = if !p.auth_str.is_empty() { &p.auth_str } else { &p.password };
            if !auth.is_empty() {
                push_kv(&mut lines, "auth-str", &ystr(auth));
            }
            if !p.obfs.is_empty() {
                push_kv(&mut lines, "obfs", &ystr(&p.obfs));
            }
            if !p.obfs_param.is_empty() {
                push_kv(&mut lines, "obfs-param", &ystr(&p.obfs_param));
            }
            push_kv(
                &mut lines,
                "protocol",
                &ystr(if p.network.is_empty() { "udp" } else { p.network.as_str() }),
            );
            push_kv(&mut lines, "up", &ystr(p.up.as_deref().unwrap_or("100 Mbps")));
            push_kv(&mut lines, "down", &ystr(p.down.as_deref().unwrap_or("100 Mbps")));
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
            if p.skip_cert_verify {
                push_kv(&mut lines, "skip-cert-verify", "true");
            }
            if !p.alpn.is_empty() {
                format_string_list(&mut lines, "alpn", &p.alpn, 4);
            }
        }
        "tuic" => {
            push_kv(&mut lines, "type", "tuic");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "uuid", &ystr(&p.uuid));
            if !p.password.is_empty() {
                push_kv(&mut lines, "password", &ystr(&p.password));
            }
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
            if let Some(ref cc) = p.congestion_control {
                push_kv(&mut lines, "congestion-controller", &ystr(cc));
            }
            if let Some(ref um) = p.udp_relay_mode {
                push_kv(&mut lines, "udp-relay-mode", &ystr(um));
            }
            if p.skip_cert_verify {
                push_kv(&mut lines, "skip-cert-verify", "true");
            }
            if !p.alpn.is_empty() {
                format_string_list(&mut lines, "alpn", &p.alpn, 4);
            }
        }
        "wireguard" | "wg" => {
            let wg_peer_pub = if !p.peer_public_key.trim().is_empty() {
                p.peer_public_key.trim()
            } else {
                p.public_key.trim()
            };
            if !is_valid_curve25519_key(&p.private_key) || !is_valid_curve25519_key(wg_peer_pub) {
                return None;
            }
            push_kv(&mut lines, "type", "wireguard");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &if p.server_port == 0 { 51820 } else { p.server_port }.to_string());
            let ip_re = Regex::new(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$").unwrap();
            let raw_addrs: Vec<&str> = p.local_address.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            let v4 = raw_addrs
                .iter()
                .find(|s| ip_re.is_match(s))
                .map(|s| s.split('/').next().unwrap_or("10.0.0.2"))
                .unwrap_or("10.0.0.2");
            push_kv(&mut lines, "ip", &ystr(v4));
            if let Some(ref v6) = p.ipv6 {
                let v6_clean = v6.split('/').next().unwrap_or(v6).trim();
                if !v6_clean.is_empty() {
                    push_kv(&mut lines, "ipv6", &ystr(v6_clean));
                }
            }
            push_kv(&mut lines, "private-key", &ystr(p.private_key.trim()));
            push_kv(&mut lines, "public-key", &ystr(wg_peer_pub));
            if is_valid_curve25519_key(&p.preshared_key) {
                push_kv(&mut lines, "pre-shared-key", &ystr(p.preshared_key.trim()));
            }
            if let Some(ref res) = p.reserved {
                if !res.is_empty() {
                    let s: Vec<String> = res.iter().map(|n| n.to_string()).collect();
                    push_kv(&mut lines, "reserved", &format!("[{}]", s.join(", ")));
                }
            }
            push_kv(&mut lines, "mtu", &p.mtu.unwrap_or(1420).to_string());
            push_kv(&mut lines, "udp", "true");
            push_kv(&mut lines, "remote-dns-resolve", &p.remote_dns_resolve.unwrap_or(true).to_string());
            if !p.dns.is_empty() {
                format_string_list(&mut lines, "dns", &p.dns, 4);
            } else {
                lines.push("    dns: [1.1.1.1, 8.8.8.8]".to_string());
            }
            if let Some(ref awg) = p.amnezia_options {
                lines.push("    amnezia-wg-option:".to_string());
                if let Some(v) = awg.jc { lines.push(format!("      jc: {}", v)); }
                if let Some(v) = awg.jmin { lines.push(format!("      jmin: {}", v)); }
                if let Some(v) = awg.jmax { lines.push(format!("      jmax: {}", v)); }
                if let Some(v) = awg.s1 { lines.push(format!("      s1: {}", v)); }
                if let Some(v) = awg.s2 { lines.push(format!("      s2: {}", v)); }
                if let Some(v) = awg.s3 { lines.push(format!("      s3: {}", v)); }
                if let Some(v) = awg.s4 { lines.push(format!("      s4: {}", v)); }
                if let Some(ref v) = awg.h1 { lines.push(format!("      h1: {}", ystr(v))); }
                if let Some(ref v) = awg.h2 { lines.push(format!("      h2: {}", ystr(v))); }
                if let Some(ref v) = awg.h3 { lines.push(format!("      h3: {}", ystr(v))); }
                if let Some(ref v) = awg.h4 { lines.push(format!("      h4: {}", ystr(v))); }
                if let Some(ref v) = awg.i1 { lines.push(format!("      i1: {}", ystr(v))); }
            }
        }
        "ssh" => {
            push_kv(&mut lines, "type", "ssh");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &if p.server_port == 0 { 22 } else { p.server_port }.to_string());
            push_kv(&mut lines, "username", &ystr(if p.username.is_empty() { "root" } else { p.username.as_str() }));
            if !p.password.is_empty() {
                push_kv(&mut lines, "password", &ystr(&p.password));
            }
            if let Some(ref pk) = p.ssh_private_key {
                if !pk.is_empty() {
                    push_kv(&mut lines, "private-key", &ystr(pk));
                }
            }
        }
        "anytls" => {
            push_kv(&mut lines, "type", "anytls");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "password", &ystr(&p.password));
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
            if !p.fingerprint.is_empty() {
                push_kv(&mut lines, "client-fingerprint", &ystr(&p.fingerprint));
            }
            if !p.alpn.is_empty() {
                format_string_list(&mut lines, "alpn", &p.alpn, 4);
            }
            if p.skip_cert_verify {
                push_kv(&mut lines, "skip-cert-verify", "true");
            }
            if let Some(ref ici) = p.idle_session_check_interval {
                if let Ok(n) = ici.trim_end_matches('s').parse::<u64>() {
                    push_kv(&mut lines, "idle-session-check-interval", &n.to_string());
                }
            }
            if let Some(ref ist) = p.idle_session_timeout {
                if let Ok(n) = ist.trim_end_matches('s').parse::<u64>() {
                    push_kv(&mut lines, "idle-session-timeout", &n.to_string());
                }
            }
            if let Some(mis) = p.min_idle_session {
                push_kv(&mut lines, "min-idle-session", &mis.to_string());
            }
            push_kv(&mut lines, "udp", "true");
        }
        "naive" | "naive+https" => {
            push_kv(&mut lines, "type", "http");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            if !p.username.is_empty() {
                push_kv(&mut lines, "username", &ystr(&p.username));
            }
            if !p.password.is_empty() {
                push_kv(&mut lines, "password", &ystr(&p.password));
            }
            push_kv(&mut lines, "tls", "true");
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
        }
        "masque" => {
            push_kv(&mut lines, "type", "masque");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &if p.server_port == 0 { 443 } else { p.server_port }.to_string());
            let norm_priv = normalize_ec_private_key(&p.private_key);
            if !norm_priv.is_empty() {
                push_kv(&mut lines, "private-key", &ystr(&norm_priv));
            }
            let pubk = if !p.public_key.is_empty() {
                p.public_key.as_str()
            } else if !p.peer_public_key.is_empty() {
                p.peer_public_key.as_str()
            } else {
                DEFAULT_MASQUE_WARP_PUBKEY
            };
            push_kv(&mut lines, "public-key", &ystr(pubk));
            if !p.local_address.is_empty() {
                let first_v4 = p.local_address.split(',').next().unwrap_or("172.16.0.2").trim();
                push_kv(&mut lines, "ip", &ystr(first_v4));
            } else {
                push_kv(&mut lines, "ip", "\"172.16.0.2\"");
            }
            if let Some(mtu) = p.mtu {
                push_kv(&mut lines, "mtu", &mtu.to_string());
            }
            push_kv(&mut lines, "udp", "true");
        }
        "snell" => {
            push_kv(&mut lines, "type", "snell");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "psk", &ystr(if !p.psk.is_empty() { &p.psk } else { &p.password }));
            if let Some(ver) = p.version {
                push_kv(&mut lines, "version", &ver.to_string());
            }
        }
        "shadowquic" => {
            push_kv(&mut lines, "type", "shadowquic");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "username", &ystr(&p.username));
            push_kv(&mut lines, "password", &ystr(&p.password));
            if !p.sni.is_empty() {
                push_kv(&mut lines, "server-name", &ystr(&p.sni));
            }
        }
        "trusttunnel" => {
            push_kv(&mut lines, "type", "trusttunnel");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "username", &ystr(&p.username));
            push_kv(&mut lines, "password", &ystr(&p.password));
            if !p.sni.is_empty() {
                push_kv(&mut lines, "sni", &ystr(&p.sni));
            }
            if p.skip_cert_verify {
                push_kv(&mut lines, "skip-cert-verify", "true");
            }
        }
        "sudoku" => {
            push_kv(&mut lines, "type", "sudoku");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "key", &ystr(&p.password));
        }
        "mieru" => {
            push_kv(&mut lines, "type", "mieru");
            push_kv(&mut lines, "server", &ystr(p.server.trim()));
            push_kv(&mut lines, "port", &p.server_port.to_string());
            push_kv(&mut lines, "username", &ystr(&p.username));
            push_kv(&mut lines, "password", &ystr(&p.password));
            push_kv(&mut lines, "transport", &ystr(if p.network.is_empty() { "TCP" } else { p.network.as_str() }));
        }
        "tailscale" => {
            push_kv(&mut lines, "type", "tailscale");
            if let Some(ref ak) = p.tailscale_auth_key {
                push_kv(&mut lines, "auth-key", &ystr(ak));
            }
        }
        "easytier" => {
            push_kv(&mut lines, "type", "easytier");
            if !p.username.is_empty() {
                push_kv(&mut lines, "network-name", &ystr(&p.username));
            }
            if let Some(ref sec) = p.network_secret {
                push_kv(&mut lines, "network-secret", &ystr(sec));
            }
        }
        "shadowtls" => {
            // Validated against Mihomo: shadowtls can use SS/Trojan wrapping or direct plugin
            if !p.cipher.is_empty() {
                push_kv(&mut lines, "type", "ss");
                push_kv(&mut lines, "server", &ystr(p.server.trim()));
                push_kv(&mut lines, "port", &p.server_port.to_string());
                push_kv(&mut lines, "cipher", &ystr(&p.cipher));
                push_kv(&mut lines, "password", &ystr(&p.password));
                push_kv(&mut lines, "plugin", "\"shadow-tls\"");
                lines.push("    plugin-opts:".to_string());
                lines.push(format!("      host: {}", ystr(if p.sni.is_empty() { &p.server } else { &p.sni })));
                lines.push(format!("      password: {}", ystr(if p.psk.is_empty() { &p.password } else { &p.psk })));
                lines.push(format!("      version: {}", p.version.unwrap_or(3)));
            } else {
                return None;
            }
        }
        _ => return None,
    }

    Some(lines.join("\n"))
}

pub fn build_mihomo_config(
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

    let mut proxies_yaml = Vec::new();
    let mut proxy_names = Vec::new();
    let mut used_names = HashSet::new();

    for (i, p) in profiles.iter().enumerate() {
        let base_name = remove_control_chars(&p.name);
        let base_name = if base_name.is_empty() {
            format!("Proxy-{}", i + 1)
        } else {
            base_name
        };
        let mut unique_name = base_name.clone();
        let mut cnt = 1usize;
        while !used_names.insert(unique_name.clone()) {
            unique_name = format!("{} #{}", base_name, cnt);
            cnt += 1;
        }
        let mut p_copy = p.clone();
        p_copy.name = unique_name.clone();
        if let Some(formatted) = format_proxy_yaml(&p_copy) {
            proxies_yaml.push(formatted);
            proxy_names.push(ystr(&unique_name));
        }
    }

    let proxy_names_list_yaml = if proxy_names.is_empty() {
        "      - \"DIRECT\"".to_string()
    } else {
        proxy_names
            .iter()
            .map(|n| format!("      - {}", n))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let proxies_section = if proxies_yaml.is_empty() {
        "  - name: \"DIRECT\"\n    type: direct".to_string()
    } else {
        proxies_yaml.join("\n\n")
    };

    let rendered_groups = GROUPS_TEMPLATE.replace("__PROXIES_PLACEHOLDER__", &proxy_names_list_yaml);
    let full = format!(
        "{}\n\nproxies:\n{}\n\n{}\n{}\n",
        HEADER_BLOCK.trim_end(),
        proxies_section,
        rendered_groups.trim_end(),
        RULES_BLOCK.trim_end()
    );
    full.chars()
        .filter(|&c| {
            let u = c as u32;
            u >= 0x20 || matches!(c, '\n' | '\r' | '\t')
        })
        .collect()
}
