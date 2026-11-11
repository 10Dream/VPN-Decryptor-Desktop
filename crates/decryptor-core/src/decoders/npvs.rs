use crate::crypto_utils::{base64_url_decode, chacha20_poly1305_open, pbkdf2_hmac_sha256};
use crate::decoders::npvs_gen2::decrypt_npvs_gen2;
use crate::models::DecryptionError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::OnceLock;

static NPVS_V1_WB_BIN: &[u8] = include_bytes!("../../assets/npvs_v1_wb.bin");

struct NpvsV1Tables {
    tlast1: Vec<u8>,   // 4096
    tlast2: Vec<u8>,   // 4096
    ty: [[u32; 256]; 16],
    mbl: [[u32; 256]; 16],
    xor_bin: Vec<u8>,  // 24576
}

static NPVS_V1_TABLES: OnceLock<NpvsV1Tables> = OnceLock::new();

fn v1_tables() -> &'static NpvsV1Tables {
    NPVS_V1_TABLES.get_or_init(|| {
        let raw = NPVS_V1_WB_BIN;
        assert_eq!(raw.len(), 65536, "Invalid NPVS v1 table size");
        let tlast1 = raw[0..4096].to_vec();
        let tlast2 = raw[4096..8192].to_vec();
        let ty_raw = &raw[8192..24576];
        let mbl_raw = &raw[24576..40960];
        let xor_bin = raw[40960..65536].to_vec();

        let mut ty = [[0u32; 256]; 16];
        let mut mbl = [[0u32; 256]; 16];
        for i in 0..16 {
            for j in 0..256 {
                let k = (i * 256 + j) * 4;
                ty[i][j] = u32::from_be_bytes([ty_raw[k], ty_raw[k + 1], ty_raw[k + 2], ty_raw[k + 3]]);
                mbl[i][j] = u32::from_be_bytes([mbl_raw[k], mbl_raw[k + 1], mbl_raw[k + 2], mbl_raw[k + 3]]);
            }
        }
        NpvsV1Tables {
            tlast1,
            tlast2,
            ty,
            mbl,
            xor_bin,
        }
    })
}

const WB_SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

#[inline]
fn wb_shift(s: &mut [u8; 16]) {
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = s[WB_SHIFT_ROWS[i]];
    }
    *s = t;
}

#[inline]
fn wb_xor(xor_bin: &[u8], t: usize, a: u32, b: u32) -> u8 {
    xor_bin[(t << 8) + ((a as usize) << 4) + (b as usize)]
}

#[inline]
fn wb_mix(xor_bin: &[u8], grp: usize, k: usize, a: u32, b: u32, c: u32, d: u32) -> u8 {
    let t = grp * 24 + k * 6;
    let hi = 28 - 8 * k;
    let lo = 24 - 8 * k;
    let p1 = wb_xor(xor_bin, t, (a >> hi) & 15, (b >> hi) & 15) as u32;
    let p2 = wb_xor(xor_bin, t + 1, (c >> hi) & 15, (d >> hi) & 15) as u32;
    let p3 = wb_xor(xor_bin, t + 2, (a >> lo) & 15, (b >> lo) & 15) as u32;
    let p4 = wb_xor(xor_bin, t + 3, (c >> lo) & 15, (d >> lo) & 15) as u32;
    (wb_xor(xor_bin, t + 4, p1, p2) << 4) | wb_xor(xor_bin, t + 5, p3, p4)
}

#[inline]
fn wb_apply_row(xor_bin: &[u8], s: &mut [u8; 16], base: usize, tab: &[[u32; 256]; 16], grp: usize) {
    let a = tab[base][s[base] as usize];
    let b = tab[base + 1][s[base + 1] as usize];
    let c = tab[base + 2][s[base + 2] as usize];
    let d = tab[base + 3][s[base + 3] as usize];
    for k in 0..4 {
        s[base + k] = wb_mix(xor_bin, grp, k, a, b, c, d);
    }
}

fn wb_block(tbl: &NpvsV1Tables, in_block: &[u8; 16], tlast: &[u8]) -> [u8; 16] {
    let mut s = *in_block;
    wb_shift(&mut s);
    for grp in 0..4 {
        let base = grp * 4;
        wb_apply_row(&tbl.xor_bin, &mut s, base, &tbl.ty, grp);
        wb_apply_row(&tbl.xor_bin, &mut s, base, &tbl.mbl, grp);
    }
    wb_shift(&mut s);
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = tlast[i * 256 + s[i] as usize];
    }
    out
}

fn wb_ctr(tbl: &NpvsV1Tables, nonce: &[u8], ct: &[u8], tlast: &[u8]) -> Vec<u8> {
    let mut counter = [0u8; 16];
    counter.copy_from_slice(&nonce[..16]);
    let mut out = vec![0u8; ct.len()];

    for i in (0..ct.len()).step_by(16) {
        let ks = wb_block(tbl, &counter, tlast);
        let n = (ct.len() - i).min(16);
        for j in 0..n {
            out[i + j] = ct[i + j] ^ ks[j];
        }
        for p in (0..16).rev() {
            counter[p] = counter[p].wrapping_add(1);
            if counter[p] != 0 {
                break;
            }
        }
    }
    out
}

fn custodian_kdks(salt: &[u8]) -> [[u8; 32]; 2] {
    let tbl = v1_tables();
    let mut material = [0u8; 32];
    let copy_len = salt.len().min(16);
    material[..copy_len].copy_from_slice(&salt[..copy_len]);
    let prefix = b"npvtunnel/appkey/v1 ";

    let mut kdks = [[0u8; 32]; 2];
    for (idx, tlast) in [&tbl.tlast1, &tbl.tlast2].iter().enumerate() {
        let stream = wb_ctr(tbl, &material[..16], &material[16..32], tlast);
        let mut hasher = Sha256::new();
        hasher.update(prefix);
        hasher.update(&stream);
        let digest = hasher.finalize();
        kdks[idx].copy_from_slice(&digest);
    }
    kdks
}

const NPVS_SENTINEL_PREFIX: &str = "npvs1:";
const NPVS_SENTINEL_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";

pub fn decode_npv_sentinels_text(s_in: &str) -> String {
    let mut result = String::new();
    let mut s = s_in;
    while let Some(idx) = s.find(NPVS_SENTINEL_PREFIX) {
        result.push_str(&s[..idx]);
        s = &s[idx + NPVS_SENTINEL_PREFIX.len()..];
        let mut j = 0;
        for (byte_idx, ch) in s.char_indices() {
            if !NPVS_SENTINEL_ALPHABET.contains(ch) {
                break;
            }
            j = byte_idx + ch.len_utf8();
        }
        let tok = &s[..j];
        s = &s[j..];
        if let Ok(dec_bytes) = base64_url_decode(tok) {
            result.push_str(&String::from_utf8_lossy(&dec_bytes));
        } else {
            result.push_str(NPVS_SENTINEL_PREFIX);
            result.push_str(tok);
        }
    }
    result.push_str(s);
    result
}

fn decode_sentinels_in_value(val: Value) -> Value {
    match val {
        Value::String(s) => {
            if let Some(tok) = s.strip_prefix(NPVS_SENTINEL_PREFIX) {
                if let Ok(bytes) = base64_url_decode(tok) {
                    let dec = String::from_utf8_lossy(&bytes).into_owned();
                    if let Ok(parsed) = serde_json::from_str::<Value>(&dec) {
                        return parsed;
                    }
                    return Value::String(dec);
                }
            }
            Value::String(s)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(decode_sentinels_in_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k, decode_sentinels_in_value(v));
            }
            Value::Object(out)
        }
        other => other,
    }
}

#[derive(Debug, Clone)]
pub struct NpvsDecoded {
    pub version: u8,
    pub config_id: String,
    pub used_method: String,
    pub policy: Value,
    pub profiles: Vec<Value>,
}

pub fn decrypt_npvs(raw_bytes: &[u8], password: &str) -> Result<NpvsDecoded, DecryptionError> {
    if raw_bytes.len() < 9 {
        return Err(DecryptionError::plain("فایل NPVS بیش از حد کوتاه است."));
    }
    if &raw_bytes[0..4] != b"NPVS" {
        return Err(DecryptionError::plain(
            "فرمت فایل نامعتبر است (شناسه NPVS یافت نشد).",
        ));
    }

    let version = raw_bytes[4];
    if version == 5 {
        return decrypt_npvs_gen2(raw_bytes, password);
    }
    if version > 1 {
        return Err(DecryptionError::plain(format!(
            "این فایل با نسخه جدید NapsternetV (نسخه {}) ذخیره شده است.",
            version
        )));
    }

    let hdr_len = u32::from_be_bytes([raw_bytes[5], raw_bytes[6], raw_bytes[7], raw_bytes[8]]) as usize;
    if 9 + hdr_len > raw_bytes.len() {
        return Err(DecryptionError::plain("طول هدر NPVS نامعتبر است."));
    }

    let header_raw = &raw_bytes[9..9 + hdr_len];
    let hdr_str = std::str::from_utf8(header_raw).map_err(|_| {
        DecryptionError::plain("قالب هدر NPVS استاندارد JSON نیست.")
    })?;
    let hdr: Value = serde_json::from_str(hdr_str).map_err(|_| {
        DecryptionError::plain("قالب هدر NPVS استاندارد JSON نیست (احتمالاً نسخه ۵ یا قفل اختصاصی).")
    })?;

    let mut off = 9 + hdr_len;
    if off + 16 > raw_bytes.len() {
        return Err(DecryptionError::plain("بخش بدنه فایل ناقص است."));
    }
    let nonce = &raw_bytes[off..off + 12];
    let body_len = u32::from_be_bytes([
        raw_bytes[off + 12],
        raw_bytes[off + 13],
        raw_bytes[off + 14],
        raw_bytes[off + 15],
    ]) as usize;
    off += 16;

    if body_len < 16 || off + body_len > raw_bytes.len() {
        return Err(DecryptionError::plain("طول دیتای رمزشده نامعتبر است."));
    }
    let body = &raw_bytes[off..off + body_len];

    let mut dek: Option<Vec<u8>> = None;
    let mut used_method = String::new();

    // Case 1: AppKey unwrapping
    if let (Some(salt_s), Some(wrap_s)) = (
        hdr.get("appKey").and_then(|v| v.get("salt")).and_then(|v| v.as_str()),
        hdr.get("appKey").and_then(|v| v.get("wrap")).and_then(|v| v.as_str()),
    ) {
        if let (Ok(salt), Ok(wrap)) = (base64_url_decode(salt_s), base64_url_decode(wrap_s)) {
            if wrap.len() >= 28 {
                for kdk in custodian_kdks(&salt) {
                    if let Ok(key) = chacha20_poly1305_open(&kdk, &wrap[0..12], &wrap[12..], &salt) {
                        dek = Some(key);
                        used_method = "appKey-custodian".to_string();
                        break;
                    }
                }
            }
        }
    }

    // Case 2: Passphrase unwrapping
    if dek.is_none() {
        if let (Some(salt_s), Some(wrap_s)) = (
            hdr.get("passphrase").and_then(|v| v.get("salt")).and_then(|v| v.as_str()),
            hdr.get("passphrase").and_then(|v| v.get("wrap")).and_then(|v| v.as_str()),
        ) {
            let display_msg = hdr
                .get("policy")
                .and_then(|v| v.get("displayMessage"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if password.trim().is_empty() {
                return Err(DecryptionError::needs_password(
                    "این کانفیگ دارای رمز عبور است.",
                    display_msg,
                ));
            }

            let salt = base64_url_decode(salt_s)
                .map_err(|e| DecryptionError::plain(format!("Salt نامعتبر: {}", e)))?;
            let wrap = base64_url_decode(wrap_s)
                .map_err(|e| DecryptionError::plain(format!("Wrap نامعتبر: {}", e)))?;
            let iters = hdr
                .get("passphrase")
                .and_then(|v| v.get("iters"))
                .and_then(|v| v.as_u64())
                .unwrap_or(10000) as u32;

            let raw_p = password.trim();
            let stripped = raw_p.strip_prefix('@').unwrap_or(raw_p);
            let raw_candidates = vec![
                raw_p.to_string(),
                if raw_p.starts_with('@') {
                    stripped.to_string()
                } else {
                    format!("@{}", raw_p)
                },
                raw_p.to_lowercase(),
                stripped.to_lowercase(),
                format!("@{}", stripped.to_lowercase()),
                raw_p.to_uppercase(),
            ];
            let mut seen = HashSet::new();
            let mut unique_cands = Vec::new();
            for c in raw_candidates {
                if !c.is_empty() && seen.insert(c.clone()) {
                    unique_cands.push(c);
                }
            }

            if wrap.len() >= 28 {
                for cand in unique_cands {
                    let pass_key = pbkdf2_hmac_sha256(cand.as_bytes(), &salt, iters);
                    if let Ok(key) =
                        chacha20_poly1305_open(&pass_key, &wrap[0..12], &wrap[12..], &salt)
                    {
                        dek = Some(key);
                        used_method = "passphrase".to_string();
                        break;
                    }
                }
            }

            if dek.is_none() {
                return Err(DecryptionError::invalid_password(
                    "رمز عبور وارد شده برای این فایل نادرست است.",
                ));
            }
        }
    }

    let dek_bytes = dek.ok_or_else(|| {
        DecryptionError::plain("کلید رمزگشایی منطبق بر فایل NPVS یافت نشد.")
    })?;

    let pt_buf = chacha20_poly1305_open(&dek_bytes, nonce, body, header_raw)
        .map_err(|e| DecryptionError::plain(format!("خطا در باز کردن بدنه NPVS: {}", e)))?;
    let raw_text = String::from_utf8_lossy(&pt_buf).into_owned();

    let parsed: Option<Value> = if let Ok(v) = serde_json::from_str::<Value>(&raw_text) {
        Some(decode_sentinels_in_value(v))
    } else {
        let cleaned = decode_npv_sentinels_text(&raw_text);
        serde_json::from_str::<Value>(&cleaned).ok()
    };

    let profiles = match parsed {
        Some(Value::Array(arr)) => arr,
        Some(Value::Object(ref map)) => {
            if let Some(Value::Array(cfgs)) = map.get("configs") {
                cfgs.clone()
            } else {
                vec![parsed.unwrap()]
            }
        }
        Some(other) => vec![other],
        None => Vec::new(),
    };

    Ok(NpvsDecoded {
        version,
        config_id: hdr
            .get("configId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        used_method,
        policy: hdr.get("policy").cloned().unwrap_or(Value::Null),
        profiles,
    })
}
