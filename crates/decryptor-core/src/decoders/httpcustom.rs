use crate::crypto_utils::{base64_decode_safe, chacha20_legacy_xor, decrypt_aes_ecb};
use crate::models::{DnsCompanionEntry};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;

const CHACHA_KEYS: [[u8; 32]; 8] = [
    [0x2b,0xe4,0x34,0x29,0x43,0xc6,0xf9,0x1f,0xf5,0x89,0x87,0xf4,0x1a,0x1a,0xaf,0xd1,0x79,0xee,0xb4,0xe0,0x53,0xf5,0xce,0xa5,0x5b,0x11,0xd6,0xa7,0xdb,0x58,0xbd,0x7d],
    [0x33,0x80,0xaa,0x27,0x8b,0x74,0x4b,0xa5,0xb5,0x29,0xa7,0xf3,0x2f,0xa8,0x03,0xe4,0x87,0x49,0x28,0x0d,0xae,0x37,0x83,0x45,0xd9,0xb5,0x26,0xcf,0x1d,0xbc,0xe3,0x72],
    [0xce,0xa9,0x30,0x5c,0x95,0x16,0x8b,0x16,0x2a,0x33,0x5b,0x13,0x7c,0x61,0x98,0x3b,0x8d,0xf5,0x4e,0x63,0x75,0xda,0x01,0x13,0x65,0x47,0x89,0x0f,0x14,0xc5,0xfa,0xc3],
    [0x4b,0xee,0xac,0xe0,0xe4,0x2b,0xae,0x8f,0x29,0x47,0x0c,0xf4,0x0c,0xf2,0xdf,0xac,0xd5,0xf4,0xe1,0xf7,0x51,0x91,0x2b,0xf5,0x2e,0x80,0x3c,0x8c,0x85,0x79,0x21,0x93],
    [0xf8,0xe5,0xf6,0xeb,0xea,0x90,0x55,0x8e,0xb3,0x22,0x29,0xda,0x24,0xfd,0x0f,0xb7,0xd8,0x13,0x09,0x1d,0xaf,0xe8,0x9b,0xb2,0x95,0x4f,0xda,0x33,0xb4,0xc6,0x0f,0x63],
    [0x81,0x34,0x2f,0x55,0x8a,0x62,0x73,0xba,0xc4,0x54,0x8d,0x47,0x3f,0x54,0xc4,0xff,0xc7,0xc4,0x17,0x47,0xde,0xe8,0x13,0x69,0xac,0xab,0x9c,0x78,0x7d,0x41,0xab,0x9c],
    [0x45,0x63,0x5e,0x6f,0xc7,0x04,0x86,0xe2,0xfd,0x10,0xd3,0xc2,0xb4,0x78,0x0f,0x02,0xd0,0xb4,0xc5,0xf4,0xaa,0x92,0x9f,0xc5,0x4f,0x86,0xbb,0x8f,0xa4,0x41,0x79,0x44],
    [0x3d,0x63,0x2a,0x25,0x1c,0x98,0x20,0xf2,0xba,0xf8,0x3e,0x15,0x49,0x8d,0x27,0x54,0x8f,0xc6,0x79,0x21,0xcb,0x43,0x7f,0x8c,0xe4,0x85,0x05,0x98,0x93,0x78,0xad,0xea],
];

const RST_KEYS: [&[u8; 16]; 9] = [
    b"JN1k3YHc2.6_v235",
    b"JN1k3YHc_2.7_v71",
    b"JN1k3YHc2.7.ps69",
    b"JN1k3YHc2.7.6950",
    b"Jn1K3yHc2.8.ps08",
    b"Jn1K3yHc2.9.ps6c",
    b"Zk:L7>WKaiK*s9>D",
    b"!<f!&WIlM**R.B0X",
    b"b4a5opinx2uloec6",
];

const JKL_KEY_OLD: [u8; 20] = [
    0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc,
    0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4,
];

const JKL_KEY_NEW: [u8; 20] = [
    8, 9, 10, 11, 12, 13, 14, 15, 17, 17,
    5, 4, 3, 2, 1, 0, 255, 254, 253, 252,
];

const RST_XOR_KEY: [u8; 20] = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21];
const STATIC_NONCE: [u8; 8] = [0xdb; 8];
const INITIAL_XOR_KEY: [u8; 11] = [0xe3,0x82,0xe4,0xb8,0xad,0xc3,0x86,0xf0,0x9f,0x92,0x93];
const BRAILLE_ALPHABET: &str = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚";

fn token_name(idx: usize) -> String {
    match idx {
        0 => "payload",
        1 => "proxy",
        2 => "lockAllConfig",
        3 => "blockedByRoot",
        4 => "expiryTime",
        5 => "noteEnabled",
        6 => "notes",
        7 => "sshField",
        8 => "mobileDataAndLockProvider",
        9 => "unlockUserAndPass",
        10 => "ovpnConfig",
        11 => "ovpnUserAndPass",
        12 => "sni",
        13 => "unlockUserAndPass2",
        14 => "unknown14",
        15 => "blockedByHwid",
        16 => "cloudconfig",
        17 => "psiphon",
        18 => "name",
        19 => "blockArea",
        20 => "connectionMode",
        21 => "blockedByPassword",
        22 => "unknown22",
        23 => "extraSniffer",
        24 => "psiphon2",
        25 => "v2rayEnabled",
        26 => "v2rayConfig",
        27 => "version",
        28 => "slowdnsEnabled",
        29 => "slowdnsServer",
        30 => "slowdnsPublickey",
        31 => "dnsResolver",
        _ => return format!("field_{}", idx),
    }
    .to_string()
}

fn clean_hex(s: &str) -> String {
    let mut clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        clean.insert(0, '0');
    }
    clean
}

fn is_hex(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_mostly_printable(s: &str, strict: bool) -> bool {
    if s.is_empty() {
        return false;
    }
    let char_len = s.chars().count();
    if char_len < 4 {
        return true;
    }
    let printable = s
        .chars()
        .filter(|&ch| {
            let c = ch as u32;
            (32..=126).contains(&c) || matches!(c, 9 | 10 | 13) || (0x0600..=0x06ff).contains(&c)
        })
        .count();
    (printable as f64) / (char_len as f64) > if strict { 0.90 } else { 0.80 }
}

fn abc_decrypt(raw_input: &str, key: &[u8; 32], nonce: &[u8; 8]) -> String {
    if raw_input.is_empty() {
        return String::new();
    }
    let hex_s = clean_hex(raw_input);
    let Ok(data) = hex::decode(hex_s) else {
        return String::new();
    };
    if data.len() > 16 {
        if let Ok(dec) = chacha20_legacy_xor(key, nonce, &data[..data.len() - 16], 1) {
            return String::from_utf8_lossy(&dec).into_owned();
        }
    }
    String::new()
}

fn jkl_decrypt(input_str: &str, is_new: bool) -> String {
    if input_str.is_empty() {
        return String::new();
    }
    let active_key = if is_new { &JKL_KEY_NEW } else { &JKL_KEY_OLD };
    let Ok(mut data) = base64_decode_safe(input_str) else {
        return input_str.to_string();
    };
    for (i, b) in data.iter_mut().enumerate() {
        let d = *b;
        let k = active_key[i % 20];
        *b = (((d ^ 0xff) & 0xca) | (d & 0x35)) ^ (((k ^ 0xff) & 0xca) | (k & 0x35));
    }
    let Ok(dec1) = String::from_utf8(data) else {
        return input_str.to_string();
    };
    match base64_decode_safe(&dec1) {
        Ok(dec2) => String::from_utf8(dec2).unwrap_or_else(|_| input_str.to_string()),
        Err(_) => input_str.to_string(),
    }
}

fn rst_decrypt(encrypted_str: &str) -> Option<String> {
    let enc_buf = encrypted_str.as_bytes();
    let xor_buf: Vec<u8> = enc_buf
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ RST_XOR_KEY[i % 20])
        .collect();
    let b64_str = String::from_utf8(xor_buf).ok()?;
    let aes_ct = base64_decode_safe(&b64_str).ok()?;
    for key in RST_KEYS {
        if let Ok(unpadded) = decrypt_aes_ecb(&aes_ct, key, true) {
            let s = String::from_utf8_lossy(&unpadded).into_owned();
            if s.contains("[splitConfig]") {
                return Some(s);
            }
        }
    }
    None
}

fn extract_z3a(data: &str, iv: i64) -> String {
    if data.is_empty() {
        return String::new();
    }
    let re = Regex::new(r"(-?\d+)\.(-?\d+)").unwrap();
    let mut bytes = Vec::new();
    for cap in re.captures_iter(data) {
        if let (Ok(m1), Ok(m2)) = (cap[1].parse::<i64>(), cap[2].parse::<i64>()) {
            let val11 = m1 - iv;
            let val22 = m2 - iv;
            if (0..31).contains(&val22) {
                let divisor = 1i64 << val22;
                let byte_val = val11.div_euclid(divisor).rem_euclid(256) as u8;
                bytes.push(byte_val);
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decrypt_braille(ciphertext: &str) -> String {
    let alphabet: Vec<char> = BRAILLE_ALPHABET.chars().collect();
    let chars: Vec<char> = ciphertext.chars().collect();
    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 1 < chars.len() {
        let idx1 = alphabet.iter().position(|&c| c == chars[i]);
        let idx2 = alphabet.iter().position(|&c| c == chars[i + 1]);
        if let (Some(a), Some(b)) = (idx1, idx2) {
            bytes.push(((a * 16 + b) & 255) as u8);
        }
        i += 2;
    }
    if bytes.is_empty() {
        ciphertext.to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

pub fn process_hc_credentials(raw_val_in: &str, is_ssh: bool) -> String {
    if raw_val_in.is_empty() {
        return String::new();
    }
    let mut raw_val = raw_val_in.to_string();
    if is_ssh {
        if let Some(first) = raw_val.chars().next() {
            if BRAILLE_ALPHABET.contains(first) {
                raw_val = decrypt_braille(&raw_val);
            }
        }
    }

    let z3a_re = Regex::new(r"(-?\d+)\.(-?\d+)").unwrap();
    if is_ssh {
        let pat = Regex::new(r"^([\w.-]+):([\d-]+)@(.+):(.+)$").unwrap();
        if let Some(c) = pat.captures(&raw_val) {
            let u_enc = &c[3];
            let p_enc = &c[4];
            let u_cnt = z3a_re.find_iter(u_enc).count() as i64;
            let p_cnt = z3a_re.find_iter(p_enc).count() as i64;
            let u_dec = extract_z3a(u_enc, u_cnt);
            let p_dec = extract_z3a(p_enc, p_cnt);
            let final_u = if u_dec.is_empty() { u_enc } else { &u_dec };
            let final_p = if p_dec.is_empty() { p_enc } else { &p_dec };
            return format!("{}:{}@{}:{}", &c[1], &c[2], final_u, final_p);
        }
    } else {
        let pat = Regex::new(r"^([^:]+):(.+)$").unwrap();
        if let Some(c) = pat.captures(&raw_val) {
            let u_enc = &c[1];
            let p_enc = &c[2];
            let u_cnt = z3a_re.find_iter(u_enc).count() as i64;
            let p_cnt = z3a_re.find_iter(p_enc).count() as i64;
            let u_dec = extract_z3a(u_enc, u_cnt);
            let p_dec = extract_z3a(p_enc, p_cnt);
            let final_u = if u_dec.is_empty() { u_enc } else { &u_dec };
            let final_p = if p_dec.is_empty() { p_enc } else { &p_dec };
            return format!("{}:{}", final_u, final_p);
        }
    }
    raw_val
}

fn decrypt_field(token: &str, dynamic_nonce: &[u8; 8]) -> String {
    if token.is_empty()
        || matches!(
            token,
            "true" | "false" | "lifeTime" | "[splitPsiphon][splitPsiphon]"
        )
        || token.starts_with('<')
    {
        return token.to_string();
    }

    let mut candidates: Vec<Vec<u8>> = Vec::new();
    let clean_h = clean_hex(token);
    if is_hex(&clean_h) && clean_h.len() >= 32 {
        if let Ok(b) = hex::decode(&clean_h) {
            candidates.push(b);
        }
    }
    if token.chars().count() > 16 {
        let latin1: Vec<u8> = token.encode_utf16().map(|u| (u & 0xff) as u8).collect();
        candidates.push(latin1);
        candidates.push(token.as_bytes().to_vec());
    }

    for c in candidates {
        if c.len() > 16 {
            let ct = &c[..c.len() - 16];
            for chacha_key in &CHACHA_KEYS {
                if let Ok(dec_bytes) = chacha20_legacy_xor(chacha_key, dynamic_nonce, ct, 1) {
                    let dec = String::from_utf8_lossy(&dec_bytes).into_owned();
                    for is_new in [true, false] {
                        let out = jkl_decrypt(&dec, is_new);
                        if !out.is_empty() && out != dec && is_mostly_printable(&out, false) {
                            return out;
                        }
                    }
                    if is_mostly_printable(&dec, true)
                        && (dec.contains("HTTP")
                            || dec.contains('@')
                            || dec.contains(':')
                            || dec.contains('{'))
                    {
                        return dec;
                    }
                }
            }
        }
    }

    for is_new in [true, false] {
        let out = jkl_decrypt(token, is_new);
        if !out.is_empty() && out != token && is_mostly_printable(&out, false) {
            return out;
        }
    }
    token.to_string()
}

fn extract_initial_payload(file_bytes: &[u8]) -> String {
    let utf8_str = String::from_utf8_lossy(file_bytes);
    let latin1: Vec<u8> = utf8_str.encode_utf16().map(|u| (u & 0xff) as u8).collect();
    let k_len = INITIAL_XOR_KEY.len();
    let out: Vec<u8> = latin1
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ INITIAL_XOR_KEY[i % k_len])
        .collect();
    String::from_utf8_lossy(&out).into_owned()
}

pub struct HttpCustomDecoded {
    pub version: &'static str,
    pub fields: BTreeMap<String, String>,
    pub dns_companions: Vec<DnsCompanionEntry>,
}

pub fn decrypt_http_custom(file_bytes: &[u8]) -> HttpCustomDecoded {
    let raw_text = String::from_utf8_lossy(file_bytes).into_owned();

    // Attempt Modern v2.7+ Multi-Layer Decryption
    let hex_payload = extract_initial_payload(file_bytes);
    if !hex_payload.is_empty() {
        let outer = abc_decrypt(&hex_payload, &CHACHA_KEYS[5], &STATIC_NONCE);
        if outer.starts_with('{') {
            if let Ok(json_obj) = serde_json::from_str::<Value>(&outer) {
                if let Some(map) = json_obj.as_object() {
                    let cfg_obj = map.get("cfg").and_then(|v| v.as_object());
                    let is_new_format = cfg_obj.map(|c| c.contains_key("content")).unwrap_or(false);

                    let mut hwid = String::new();
                    let mut password = String::new();
                    let mut provider = String::new();
                    let mut area = String::new();
                    let target_cipher: String;
                    let split_delim: String;

                    if is_new_format {
                        let c = cfg_obj.unwrap();
                        hwid = map
                            .get("b")
                            .or_else(|| c.get("b"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        area = map
                            .get("f")
                            .or_else(|| c.get("f"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        target_cipher = c
                            .get("content")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        split_delim = "[splitConfig]".to_string();
                    } else {
                        let obj_a = map.get("a").and_then(|v| v.as_object());
                        let get_s = |k: &str| {
                            map.get(k)
                                .or_else(|| obj_a.and_then(|a| a.get(k)))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string()
                        };
                        let bb = get_s("bb");
                        let e = get_s("e");
                        let fe = get_s("fe");
                        let ed = get_s("ed");
                        if !bb.is_empty() {
                            hwid = abc_decrypt(&bb, &CHACHA_KEYS[7], &STATIC_NONCE);
                        }
                        if !e.is_empty() {
                            password = abc_decrypt(&e, &CHACHA_KEYS[7], &STATIC_NONCE);
                        }
                        if !fe.is_empty() {
                            area = abc_decrypt(&fe, &CHACHA_KEYS[7], &STATIC_NONCE);
                        }
                        if !ed.is_empty() {
                            provider = abc_decrypt(&ed, &CHACHA_KEYS[7], &STATIC_NONCE);
                        }
                        target_cipher = get_s("xy");
                        split_delim = get_s("uv");
                    }

                    if !target_cipher.is_empty() && !split_delim.is_empty() {
                        let derived_hex = if !hwid.is_empty()
                            && password.is_empty()
                            && provider.is_empty()
                            && area.is_empty()
                        {
                            format!("{}{}", hex::encode(&hwid), hex::encode(&hwid))
                        } else {
                            format!(
                                "{}{}{}{}",
                                hex::encode(&password),
                                hex::encode(&hwid),
                                hex::encode(&provider),
                                hex::encode(&area)
                            )
                        };
                        let mut dynamic_nonce = STATIC_NONCE;
                        if !derived_hex.is_empty() {
                            let prefix: String = derived_hex.chars().take(16).collect();
                            if let Ok(d_buf) = hex::decode(prefix) {
                                for i in 0..d_buf.len().min(8) {
                                    dynamic_nonce[i] = d_buf[i];
                                }
                            }
                        }

                        let xy_dec = if is_new_format {
                            rst_decrypt(&target_cipher).or_else(|| {
                                CHACHA_KEYS.iter().find_map(|k| {
                                    let tmp = abc_decrypt(&target_cipher, k, &STATIC_NONCE);
                                    if tmp.contains(&split_delim) {
                                        Some(tmp)
                                    } else {
                                        None
                                    }
                                })
                            })
                        } else {
                            let t = abc_decrypt(&target_cipher, &CHACHA_KEYS[1], &STATIC_NONCE);
                            if t.is_empty() { None } else { Some(t) }
                        };

                        if let Some(xy) = xy_dec {
                            let mut fields = BTreeMap::new();
                            for (i, tok) in xy.split(&split_delim).enumerate() {
                                if i == 22 || i == 24 {
                                    continue;
                                }
                                let label = token_name(i);
                                let mut final_out = if is_new_format {
                                    decrypt_field(tok, &dynamic_nonce)
                                } else {
                                    let dec = if is_hex(tok) {
                                        abc_decrypt(tok, &CHACHA_KEYS[7], &dynamic_nonce)
                                    } else {
                                        tok.to_string()
                                    };
                                    jkl_decrypt(&dec, false)
                                };

                                if i == 7 {
                                    final_out = process_hc_credentials(&final_out, true);
                                } else if i == 11 {
                                    final_out = process_hc_credentials(&final_out, false);
                                }

                                if !final_out.is_empty() {
                                    final_out = final_out.replace(
                                        "88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d",
                                        "",
                                    );
                                    fields.insert(label, final_out);
                                }
                            }
                            let dns_companions = build_hc_dns_companions(&fields);
                            return HttpCustomDecoded {
                                version: "v2.7",
                                fields,
                                dns_companions,
                            };
                        }
                    }
                }
            }
        }
    }

    // Legacy / Braille Fallback
    let mut text = raw_text.trim().to_string();
    if text.chars().count() > 10 {
        if let Some(first) = text.chars().next() {
            if BRAILLE_ALPHABET.contains(first) {
                let dec = decrypt_braille(&text);
                if !dec.is_empty() {
                    text = dec;
                }
            }
        }
    }

    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(colon) = trimmed.find(':') {
            if let Ok(tok_idx) = trimmed[..colon].trim().parse::<usize>() {
                if tok_idx <= 31 {
                    fields.insert(token_name(tok_idx), trimmed[colon + 1..].trim().to_string());
                }
            }
        }
    }

    let dns_companions = build_hc_dns_companions(&fields);
    HttpCustomDecoded {
        version: "legacy",
        fields,
        dns_companions,
    }
}

fn build_hc_dns_companions(fields: &BTreeMap<String, String>) -> Vec<DnsCompanionEntry> {
    let mut out = Vec::new();
    if let Some(pub_key) = fields.get("slowdnsPublickey").filter(|s| !s.is_empty()) {
        let domain = fields.get("slowdnsServer").map(|s| s.as_str()).unwrap_or("");
        let resolver = fields
            .get("dnsResolver")
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("8.8.8.8:53");
        out.push(DnsCompanionEntry {
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
    out
}
