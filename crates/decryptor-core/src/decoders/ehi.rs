use crate::crypto_utils::{base64_decode_safe, decrypt_aes_cbc_nopad, pkcs7_unpad};
use crate::models::{DecryptionError, ProxyProfile};
use serde_json::{Map, Value};

const L1_KEY: [u8; 32] = [
    0x7e, 0x12, 0x10, 0xf7, 0xaa, 0xb9, 0x56, 0xf7, 0xa6, 0x68, 0xbd, 0xa6, 0xe5, 0x7f, 0xed, 0xdb,
    0x7f, 0x84, 0xad, 0x84, 0x0a, 0xef, 0x8d, 0x27, 0xb1, 0xb9, 0x69, 0x95, 0x9b, 0xe3, 0xab, 0x6c,
];
const L2_KEY: [u8; 16] = [
    0xb2, 0xbc, 0x61, 0x7c, 0x32, 0xd8, 0xb9, 0xeb, 0x19, 0x43, 0xa5, 0xff, 0xa8, 0x05, 0x1e, 0xea,
];
const XXTEA_KEY: &[u8] = b"null=V5kU5+FFrY\0";

struct OuterIv {
    mode: &'static str,
    iv: [u8; 16],
}

const OUTER_IVS: [OuterIv; 6] = [
    OuterIv {
        mode: "bypass",
        iv: [0x22,0x1d,0x57,0x23,0x49,0x55,0x5f,0x1d,0x11,0x21,0x33,0x23,0x6b,0x1f,0x4a,0x3f],
    },
    OuterIv {
        mode: "bypass",
        iv: [0x55,0x43,0x49,0x4c,0x53,0x44,0x3e,0x3f,0x4a,0x6a,0x45,0x39,0x38,0x4e,0x77,0x6a],
    },
    OuterIv {
        mode: "bypass",
        iv: [0x37,0x4c,0x25,0x41,0x57,0x5e,0x4d,0x53,0x1a,0x3c,0x32,0x7b,0x75,0x43,0x1e,0x5f],
    },
    OuterIv {
        mode: "locked",
        iv: [0x2c,0x5d,0x11,0x47,0xbb,0xad,0x42,0x2b,0x3b,0x33,0x4d,0x4d,0x23,0x5f,0x1a,0x53],
    },
    OuterIv {
        mode: "locked",
        iv: [0x52,0x2b,0x01,0x43,0x3a,0x5e,0x8b,0x2f,0xc7,0x54,0x9e,0x1a,0xd3,0x68,0xe5,0x41],
    },
    OuterIv {
        mode: "locked",
        iv: [0x33,0x7a,0x10,0x35,0xaa,0xed,0xf3,0x45,0x8c,0xa1,0x67,0xe9,0x2d,0x74,0xb8,0x39],
    },
];

const EHI_B64_ALPHABET: &[u8] =
    b"RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs";
const STD_B64_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const MESSAGE_XOR_KEY: &[u8] = b"EHIMSG";

fn xxtea_decrypt(data: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let n = data.len() / 4;
    if n == 0 || key_bytes.len() < 16 {
        return Vec::new();
    }
    let mut v = vec![0u32; n];
    for i in 0..n {
        v[i] = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
    }
    let mut k = [0u32; 4];
    for i in 0..4 {
        k[i] = u32::from_le_bytes([
            key_bytes[i * 4],
            key_bytes[i * 4 + 1],
            key_bytes[i * 4 + 2],
            key_bytes[i * 4 + 3],
        ]);
    }

    const DELTA: u32 = 0x9E37_79B9;
    let rounds = 6 + 52 / n as u32;
    let mut sum = rounds.wrapping_mul(DELTA);
    let mut y = v[0];
    while sum != 0 {
        let e = ((sum >> 2) & 3) as usize;
        for p in (1..n).rev() {
            let z = v[p - 1];
            let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
                ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e] ^ z));
            y = v[p].wrapping_sub(mx);
            v[p] = y;
        }
        let z = v[n - 1];
        let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
            ^ ((sum ^ y).wrapping_add(k[e] ^ z));
        y = v[0].wrapping_sub(mx);
        v[0] = y;
        sum = sum.wrapping_sub(DELTA);
    }

    let mut out = Vec::with_capacity(n * 4);
    for word in &v {
        out.extend_from_slice(&word.to_le_bytes());
    }
    if out.len() >= 4 {
        let decoded_len = u32::from_le_bytes([
            out[out.len() - 4],
            out[out.len() - 3],
            out[out.len() - 2],
            out[out.len() - 1],
        ]) as usize;
        if decoded_len > 0 && decoded_len <= out.len() {
            out.truncate(decoded_len);
            return out;
        }
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn decode_custom_b64(input: &str) -> Option<Vec<u8>> {
    let mut std_s = String::with_capacity(input.len());
    for b in input.bytes() {
        if b == b'?' || b <= b' ' {
            continue;
        }
        let pos = EHI_B64_ALPHABET.iter().position(|&c| c == b)?;
        std_s.push(STD_B64_ALPHABET[pos] as char);
    }
    base64_decode_safe(&std_s).ok()
}

pub fn decrypt_ehi_xor_field(encoded: &str, key: &str) -> String {
    if encoded.trim().is_empty() || key.is_empty() {
        return encoded.to_string();
    }
    let reversed: String = encoded.chars().rev().collect();
    let Some(decoded) = decode_custom_b64(&reversed) else {
        return encoded.to_string();
    };
    let mut hex_text = String::from_utf8_lossy(&decoded).into_owned();
    if hex_text.len() % 2 != 0 {
        hex_text.insert(0, '0');
    }
    let Ok(ct) = hex::decode(&hex_text) else {
        return encoded.to_string();
    };
    let key_bytes = key.as_bytes();
    let pt: Vec<u8> = ct
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| {
            let dec = b ^ key_bytes[i % key_bytes.len()];
            if dec == 0 { None } else { Some(dec) }
        })
        .collect();
    String::from_utf8(pt).unwrap_or_else(|_| encoded.to_string())
}

pub fn decode_ehi_message(encoded: &str) -> String {
    if encoded.is_empty() {
        return String::new();
    }
    let Ok(raw) = base64_decode_safe(encoded) else {
        return encoded.to_string();
    };
    let text = String::from_utf8_lossy(&raw);
    let units: Vec<u16> = text
        .encode_utf16()
        .enumerate()
        .map(|(i, u)| u ^ (MESSAGE_XOR_KEY[i % MESSAGE_XOR_KEY.len()] as u16))
        .collect();
    String::from_utf16_lossy(&units)
}

fn parse_file_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 10 {
        return None;
    }
    let mut off = 0usize;
    if off + 2 > buf.len() {
        return None;
    }
    let len1 = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2 + len1 + 8;
    if off + 2 > buf.len() {
        return None;
    }
    let len2 = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2 + len2 + 8;
    if off + 4 > buf.len() {
        return None;
    }
    let payload_len = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
    off += 12;
    if off + payload_len > buf.len() {
        return None;
    }
    Some(&buf[off..off + payload_len])
}

pub struct EhiDecoded {
    pub mode: &'static str,
    pub parsed: Value,
    pub raw_profiles_json: Vec<Value>,
    pub profiles: Vec<ProxyProfile>,
    pub expiry_raw: Option<String>,
}

pub fn decrypt_ehi(raw_buffer: &[u8]) -> Result<EhiDecoded, DecryptionError> {
    let payload = parse_file_payload(raw_buffer).ok_or_else(|| {
        DecryptionError::plain("ساختار هدر فایل HTTP Injector (.ehi) معتبر نیست.")
    })?;

    for cand in OUTER_IVS {
        let Ok(l1) = decrypt_aes_cbc_nopad(payload, &L1_KEY, &cand.iv) else {
            continue;
        };
        let l1_unpadded = pkcs7_unpad(&l1, 16, false).unwrap_or(l1);
        let l1_text = String::from_utf8_lossy(&l1_unpadded);
        let parts: Vec<&str> = l1_text.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        let Ok(inner_iv) = base64_decode_safe(parts[0]) else {
            continue;
        };
        let Ok(inner_cipher) = base64_decode_safe(parts[2]) else {
            continue;
        };
        if inner_iv.len() != 16 || inner_cipher.is_empty() {
            continue;
        }
        let Ok(l2) = decrypt_aes_cbc_nopad(&inner_cipher, &L2_KEY, &inner_iv) else {
            continue;
        };
        let l2_unpadded = pkcs7_unpad(&l2, 16, false).unwrap_or(l2);
        let final_bytes = xxtea_decrypt(&l2_unpadded, XXTEA_KEY);
        let s = String::from_utf8_lossy(&final_bytes);
        let (Some(start), Some(end)) = (s.find('{'), s.rfind('}')) else {
            continue;
        };
        if end <= start {
            continue;
        }
        let Ok(Value::Object(parsed_map)) = serde_json::from_str::<Value>(&s[start..=end]) else {
            continue;
        };

        let salt = parsed_map
            .get("configSalt")
            .and_then(|v| v.as_str())
            .unwrap_or("EVZJNI")
            .to_string();
        let mut cleaned = Map::new();
        for (k, v) in parsed_map {
            if k == "configMessage" {
                if let Some(st) = v.as_str() {
                    cleaned.insert(k, Value::String(decode_ehi_message(st)));
                } else {
                    cleaned.insert(k, v);
                }
            } else if let Some(st) = v.as_str() {
                cleaned.insert(k, Value::String(decrypt_ehi_xor_field(st, &salt)));
            } else {
                cleaned.insert(k, v);
            }
        }

        let get_str = |k: &str| {
            cleaned
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        let mut raw_profiles_json = Vec::new();
        if let Some(v2r_val) = cleaned.get("v2rRawJson") {
            let raw_v2r: Option<Value> = match v2r_val {
                Value::String(st) => serde_json::from_str(st).ok(),
                other => Some(other.clone()),
            };
            if let Some(outbounds) = raw_v2r.and_then(|r| r.get("outbounds").cloned()).and_then(|o| o.as_array().cloned()) {
                for ob in outbounds {
                    let proto = ob.get("protocol").and_then(|p| p.as_str()).unwrap_or("");
                    if matches!(proto, "vmess" | "vless" | "trojan" | "shadowsocks") {
                        raw_profiles_json.push(ob);
                    }
                }
            }
        }

        let mut profiles = Vec::new();
        let server_host = ["host", "server", "v2rHost", "userhost"]
            .iter()
            .find_map(|k| cleaned.get(*k).and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()))
            .unwrap_or("")
            .trim()
            .to_string();

        if !server_host.is_empty() && !server_host.contains(' ') && raw_profiles_json.is_empty() {
            let server_port = cleaned
                .get("port")
                .or_else(|| cleaned.get("v2rPort"))
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(22) as u16;
            let username = ["user", "username"]
                .iter()
                .find_map(|k| cleaned.get(*k).and_then(|v| v.as_str()))
                .unwrap_or("");
            let password = ["password", "v2rPassword"]
                .iter()
                .find_map(|k| cleaned.get(*k).and_then(|v| v.as_str()))
                .unwrap_or("");
            let raw_proto = cleaned
                .get("tunnelType")
                .or_else(|| cleaned.get("v2rProtocol"))
                .and_then(|v| v.as_str())
                .unwrap_or("ssh")
                .to_lowercase();

            let proto = if raw_proto.contains("vless") {
                "vless"
            } else if raw_proto.contains("vmess") {
                "vmess"
            } else if raw_proto.contains("trojan") {
                "trojan"
            } else if raw_proto.contains("shadowsocks") || raw_proto.contains("ss") {
                "shadowsocks"
            } else {
                "ssh"
            };

            if proto != "ssh" {
                let sec_type = get_str("v2rTleSecurityType");
                let tls = !sec_type.is_empty() && sec_type != "none";
                let net = get_str("v2rNetwork");
                let sni = get_str("sniHostname");
                let ident = get_str("configIdentifier");
                let auth_val = if !password.is_empty() { password } else { username };

                profiles.push(ProxyProfile {
                    name: if ident.is_empty() {
                        format!("EHI-{}", proto.to_uppercase())
                    } else {
                        ident
                    },
                    protocol: proto.to_string(),
                    server: server_host.clone(),
                    server_port: if server_port == 0 { 443 } else { server_port },
                    uuid: auth_val.to_string(),
                    password: auth_val.to_string(),
                    network: if net.is_empty() { "tcp".to_string() } else { net },
                    host: get_str("v2rWsHeader"),
                    sni: if sni.is_empty() { server_host } else { sni },
                    tls,
                    security: if tls { "tls" } else { "none" }.to_string(),
                    ..Default::default()
                });
            } else {
                let ident = get_str("configIdentifier");
                profiles.push(ProxyProfile {
                    name: if ident.is_empty() {
                        format!("EHI-SSH-{}", server_host)
                    } else {
                        ident
                    },
                    protocol: "ssh".to_string(),
                    server: server_host,
                    server_port: if server_port == 0 { 22 } else { server_port },
                    username: username.trim().to_string(),
                    password: password.trim().to_string(),
                    ..Default::default()
                });
            }
        }

        if profiles.is_empty() && raw_profiles_json.is_empty() {
            if cand.mode == "locked" {
                let msg = get_str("configMessage");
                let suffix = if msg.is_empty() {
                    String::new()
                } else {
                    format!(" (پیام سازنده: {})", msg)
                };
                return Err(DecryptionError::plain(format!(
                    "🔒 این فایل HTTP Injector دارای قفل اختصاصی سازنده (Author Lock) است و کانفیگ درون آن مسدود می‌باشد.{}",
                    suffix
                )));
            }
            return Err(DecryptionError::plain(
                "🔒 فایل HTTP Injector فاقد کانفیگ سرور قابل استخراج است (احتمالاً قفل شده یا خالی است).",
            ));
        }

        let expiry_raw = cleaned
            .get("configExpiryTimestamp")
            .and_then(|v| match v {
                Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });

        return Ok(EhiDecoded {
            mode: cand.mode,
            parsed: Value::Object(cleaned),
            raw_profiles_json,
            profiles,
            expiry_raw,
        });
    }

    Err(DecryptionError::plain(
        "🔒 این فایل HTTP Injector دارای قفل سازنده یا ساختار رمزگذاری سفارشی است و امکان بازگشایی آن وجود ندارد.",
    ))
}
