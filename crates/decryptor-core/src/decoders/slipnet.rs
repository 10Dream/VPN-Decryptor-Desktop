use crate::crypto_utils::{base64_decode_safe, decrypt_aes_256_gcm};
use crate::models::{DnsCompanionEntry, ProxyProfile};
use std::collections::BTreeMap;

const SLIP_KEY: [u8; 32] = [
    0x21, 0x4F, 0x05, 0x20, 0x25, 0xB2, 0xF9, 0x49, 0x60, 0x5A, 0x54, 0x29, 0xEC, 0x3D, 0x5F,
    0xA8, 0x0C, 0x20, 0x22, 0xC1, 0x68, 0xAD, 0x94, 0x6E, 0x68, 0x85, 0x2D, 0x44, 0x72, 0x14,
    0xDB, 0xD3,
];

const SCHEMA_V28: &[&str] = &[
    "Version",
    "Tunnel Type/Mode",
    "Name",
    "Domain",
    "Resolvers",
    "AuthMode",
    "KeepAlive",
    "CC",
    "Port",
    "Host",
    "GSO",
    "DNSTT Public Key",
    "SOCKS Username",
    "SOCKS Password",
    "SSH Enabled",
    "SSH Username",
    "SSH Password",
    "SSH Port",
    "Forward DNS thru SSH",
    "SSH Host",
    "Use Server DNS",
    "DoH URL",
    "DNS Transport",
    "SSH Auth Type",
    "SSH Private Key (B64)",
    "SSH Key Passphrase (B64)",
    "Tor Bridge Lines (B64)",
    "DNSTT Authoritative",
    "Naive Port",
    "Naive Username",
    "Naive Password (B64)",
    "Is Locked",
    "Lock Password Hash",
    "Expiration Date",
    "Allow Sharing",
    "Bound Device ID",
    "Resolvers Hidden",
    "Hidden Resolvers",
    "NoizDNS Stealth",
    "DNS Payload Size",
    "SOCKS5 Server Port",
    "VayDNS DNSTT Compat",
    "VayDNS Record Type",
    "VayDNS Max Qname Len",
    "VayDNS RPS",
    "VayDNS Idle Timeout",
    "VayDNS Keepalive",
    "VayDNS UDP Timeout",
    "VayDNS Max Num Labels",
    "VayDNS Client Id Size",
    "SSH TLS Enabled",
    "SSH TLS SNI",
    "SSH HTTP Proxy Host",
    "SSH HTTP Proxy Port",
    "SSH HTTP Proxy Custom Host",
    "SSH WS Enabled",
    "SSH WS Path",
    "SSH WS Use TLS",
    "SSH WS Custom Host",
    "SSH Payload (B64)",
    "Resolver Mode",
    "RR Spread Count",
    "VLESS UUID",
    "VLESS Security",
    "VLESS Transport",
    "VLESS WS Path",
    "CDN IP",
    "CDN Port",
    "SNI Fragment Enabled",
    "SNI Fragment Strategy",
    "SNI Fragment Delay MS",
    "Legacy SNI (Empty)",
    "CH Padding Enabled",
    "WS Header Obfuscation",
    "WS Padding Enabled",
    "SNI Spoof TTL",
    "Fake Decoy Host",
    "TCP Max Seg",
    "VLESS SNI",
];

pub struct SlipNetDecoded {
    pub proto: String,
    pub fields: BTreeMap<String, String>,
    pub profiles: Vec<ProxyProfile>,
    pub dns_companions: Vec<DnsCompanionEntry>,
}

pub fn decrypt_slipnet(raw_input: &str) -> SlipNetDecoded {
    let mut text = raw_input.trim();
    let mut proto = "";
    if let Some(rest) = text.strip_prefix("slipnet://") {
        proto = "slipnet";
        text = rest.trim();
    } else if let Some(rest) = text.strip_prefix("slipnet-enc://") {
        proto = "slipnet-enc";
        text = rest.trim();
    } else if let Some(rest) = text.strip_prefix("slipnet-bundle-enc://") {
        proto = "slipnet-bundle-enc";
        text = rest.trim();
    }

    let mut decoded = text.to_string();
    let looks_b64 = text.len() > 30
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'));

    if proto == "slipnet-enc" || (proto.is_empty() && looks_b64) {
        if let Ok(raw) = base64_decode_safe(text) {
            if raw.len() > 28 {
                let mut ok = false;
                if raw[0] == 0x01 && raw.len() > 29 {
                    let iv = &raw[1..13];
                    let tag = &raw[raw.len() - 16..];
                    let ct = &raw[13..raw.len() - 16];
                    if let Ok(pt) = decrypt_aes_256_gcm(&SLIP_KEY, iv, ct, tag) {
                        decoded = String::from_utf8_lossy(&pt).into_owned();
                        ok = true;
                    }
                }
                if !ok {
                    let iv = &raw[0..12];
                    let tag = &raw[raw.len() - 16..];
                    let ct = &raw[12..raw.len() - 16];
                    if let Ok(pt) = decrypt_aes_256_gcm(&SLIP_KEY, iv, ct, tag) {
                        decoded = String::from_utf8_lossy(&pt).into_owned();
                    }
                }
            }
        }
    } else if proto == "slipnet" {
        if let Ok(raw) = base64_decode_safe(text) {
            decoded = String::from_utf8_lossy(&raw).into_owned();
        }
    }

    let mut fields = BTreeMap::new();
    for (idx, val) in decoded.split('|').enumerate() {
        let key = SCHEMA_V28
            .get(idx)
            .map(|&s| s.to_string())
            .unwrap_or_else(|| format!("Field_{}", idx));
        fields.insert(key, val.to_string());
    }

    let name = fields
        .get("Name")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "SlipNet-Profile".to_string());

    let mut profiles = Vec::new();
    let get_f = |k: &str| fields.get(k).map(|s| s.as_str()).unwrap_or("");

    if !get_f("VLESS UUID").is_empty() {
        let server = if !get_f("CDN IP").is_empty() {
            get_f("CDN IP")
        } else if !get_f("Host").is_empty() {
            get_f("Host")
        } else {
            "127.0.0.1"
        };
        let port = get_f("CDN Port")
            .parse::<u16>()
            .ok()
            .or_else(|| get_f("Port").parse::<u16>().ok())
            .unwrap_or(443);
        let tls = get_f("VLESS Security") == "tls";
        let net = if get_f("VLESS Transport").is_empty() {
            "ws"
        } else {
            get_f("VLESS Transport")
        };
        let path = if get_f("VLESS WS Path").is_empty() {
            "/"
        } else {
            get_f("VLESS WS Path")
        };
        let sni = if !get_f("VLESS SNI").is_empty() {
            get_f("VLESS SNI")
        } else {
            get_f("Domain")
        };

        profiles.push(ProxyProfile {
            protocol: "vless".to_string(),
            name: format!("{}-VLESS", name),
            server: server.to_string(),
            server_port: port,
            uuid: get_f("VLESS UUID").to_string(),
            tls,
            security: if tls { "tls" } else { "none" }.to_string(),
            network: net.to_string(),
            path: path.to_string(),
            sni: sni.to_string(),
            ..Default::default()
        });
    }

    if !get_f("SSH Host").is_empty() || (get_f("SSH Enabled") == "1" && !get_f("Host").is_empty()) {
        let server = if !get_f("SSH Host").is_empty() {
            get_f("SSH Host")
        } else {
            get_f("Host")
        };
        let port = get_f("SSH Port")
            .parse::<u16>()
            .ok()
            .or_else(|| get_f("Port").parse::<u16>().ok())
            .unwrap_or(22);
        let user = if get_f("SSH Username").is_empty() {
            "root"
        } else {
            get_f("SSH Username")
        };
        let sni = if !get_f("SSH TLS SNI").is_empty() {
            get_f("SSH TLS SNI")
        } else {
            get_f("Domain")
        };
        profiles.push(ProxyProfile {
            protocol: "ssh".to_string(),
            name: format!("{}-SSH", name),
            server: server.to_string(),
            server_port: port,
            username: user.to_string(),
            password: get_f("SSH Password").to_string(),
            sni: sni.to_string(),
            tls: get_f("SSH TLS Enabled") == "1",
            network: if get_f("SSH WS Enabled") == "1" {
                "ws"
            } else {
                "tcp"
            }
            .to_string(),
            path: get_f("SSH WS Path").to_string(),
            ..Default::default()
        });
    }

    // Companion DNS & SSH entries
    let mut dns_companions = Vec::new();
    if !get_f("DNSTT Public Key").is_empty() {
        let pub_key = get_f("DNSTT Public Key");
        let domain = get_f("Domain");
        let resolver = if get_f("Resolvers").is_empty() {
            "8.8.8.8:53"
        } else {
            get_f("Resolvers")
        };
        dns_companions.push(DnsCompanionEntry {
            kind: "dnstt".to_string(),
            title: "DNSTT / SlowDNS Tunnel".to_string(),
            summary: format!(
                "🔑 کلید عمومی: {}\n🌐 دامنه: {}\n📡 ریزالور: {}",
                pub_key,
                if domain.is_empty() { "تعیین‌نشده" } else { domain },
                resolver
            ),
        });
    }
    if !get_f("DoH URL").is_empty() {
        dns_companions.push(DnsCompanionEntry {
            kind: "doh".to_string(),
            title: "DNS over HTTPS (DoH)".to_string(),
            summary: format!("🌐 آدرس DoH: {}", get_f("DoH URL")),
        });
    }

    SlipNetDecoded {
        proto: if proto.is_empty() {
            "slipnet-enc"
        } else {
            proto
        }
        .to_string(),
        fields,
        profiles,
        dns_companions,
    }
}
