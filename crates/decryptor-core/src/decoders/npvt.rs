use crate::crypto_utils::{base64_decode_safe, inflate_zlib};
use crate::models::DecryptionError;
use serde_json::Value;
use std::sync::OnceLock;

static NPVT_WB_ZLIB: &[u8] = include_bytes!("../../assets/npvt_whitebox_u32le.zlib");

struct NpvtTables {
    p2: Vec<u32>, // [96][16][16] -> 24576
    p3: Vec<u32>, // [16][256] -> 4096
    p4: Vec<u32>, // [16][256] -> 4096
    p5: Vec<u32>, // [16][256] -> 4096
}

static NPVT_TABLES: OnceLock<NpvtTables> = OnceLock::new();

fn tables() -> &'static NpvtTables {
    NPVT_TABLES.get_or_init(|| {
        let raw = inflate_zlib(NPVT_WB_ZLIB).expect("Corrupt NPVT whitebox asset");
        assert_eq!(raw.len(), 36864 * 4, "Invalid NPVT whitebox table size");
        let mut all = Vec::with_capacity(36864);
        for chunk in raw.chunks_exact(4) {
            all.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let p2 = all[0..24576].to_vec();
        let p3 = all[24576..28672].to_vec();
        let p4 = all[28672..32768].to_vec();
        let p5 = all[32768..36864].to_vec();
        NpvtTables { p2, p3, p4, p5 }
    })
}

const PERM: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

#[inline]
fn p2_at(tbl: &NpvtTables, idx: usize, a: usize, b: usize) -> u8 {
    tbl.p2[idx * 256 + a * 16 + b] as u8
}

#[inline]
fn apply_round(tbl: &NpvtTables, state: &[u8; 16], p3_or_p5: &[u32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for col in 0..4 {
        let mut t = [0u32; 4];
        for i in 0..4 {
            t[i] = p3_or_p5[(col * 4 + i) * 256 + state[col * 4 + i] as usize];
        }
        for row in 0..4 {
            let idx = col * 24 + row * 6;
            let sh_hi = 28 - row * 8;
            let sh_lo = 24 - row * 8;

            let x1_hi = p2_at(
                tbl,
                idx,
                ((t[0] >> sh_hi) & 0xF) as usize,
                ((t[1] >> sh_hi) & 0xF) as usize,
            ) as usize;
            let x2_hi = p2_at(
                tbl,
                idx + 1,
                ((t[2] >> sh_hi) & 0xF) as usize,
                ((t[3] >> sh_hi) & 0xF) as usize,
            ) as usize;
            let hi_val = p2_at(tbl, idx + 4, x1_hi, x2_hi);

            let x1_lo = p2_at(
                tbl,
                idx + 2,
                ((t[0] >> sh_lo) & 0xF) as usize,
                ((t[1] >> sh_lo) & 0xF) as usize,
            ) as usize;
            let x2_lo = p2_at(
                tbl,
                idx + 3,
                ((t[2] >> sh_lo) & 0xF) as usize,
                ((t[3] >> sh_lo) & 0xF) as usize,
            ) as usize;
            let lo_val = p2_at(tbl, idx + 5, x1_lo, x2_lo);

            out[col * 4 + row] = ((hi_val << 4) | lo_val) & 0xFF;
        }
    }
    out
}

fn whitebox_encrypt_block(block: &[u8; 16]) -> [u8; 16] {
    let tbl = tables();
    let mut state = *block;

    // r = 0: perm -> p3+p2 -> p5+p2
    let mut permuted = [0u8; 16];
    for i in 0..16 {
        permuted[i] = state[PERM[i]];
    }
    state = permuted;
    let mid_state = apply_round(tbl, &state, &tbl.p3);
    state = apply_round(tbl, &mid_state, &tbl.p5);

    // r = 1: perm -> break
    for i in 0..16 {
        permuted[i] = state[PERM[i]];
    }
    state = permuted;

    for i in 0..16 {
        state[i] = (tbl.p4[i * 256 + state[i] as usize] & 0xFF) as u8;
    }
    state
}

fn increment_counter(iv: &mut [u8; 16]) {
    for k in (0..16).rev() {
        iv[k] = iv[k].wrapping_add(1);
        if iv[k] != 0 {
            break;
        }
    }
}

pub fn decrypt_payload(raw_b64: &str) -> Result<String, String> {
    let raw = base64_decode_safe(raw_b64)?;
    if raw.len() <= 16 {
        return Err("NPVT encrypted payload too short".to_string());
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&raw[0..16]);
    let ciphertext = &raw[16..];
    let mut plaintext = vec![0u8; ciphertext.len()];

    let mut keystream = [0u8; 16];
    for (j, &ct_byte) in ciphertext.iter().enumerate() {
        let offset = j % 16;
        if offset == 0 {
            keystream = whitebox_encrypt_block(&iv);
            increment_counter(&mut iv);
        }
        plaintext[j] = ct_byte ^ keystream[offset];
    }

    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

#[derive(Debug, Clone)]
pub struct NpvtDecoded {
    pub kind: String,
    pub version: i32,
    pub profiles: Vec<Value>,
    pub settings: Option<Value>,
}

pub fn decrypt_npvt(raw_input: &str) -> Result<NpvtDecoded, DecryptionError> {
    let text = raw_input.trim_start_matches('\u{FEFF}').trim();
    let (kind, body) = if let Some(rest) = text.strip_prefix("NPVTSUB1") {
        ("NPVTSUB1".to_string(), rest.trim())
    } else if let Some(rest) = text.strip_prefix("NPVT1") {
        ("NPVT1".to_string(), rest.trim())
    } else if let Some(rest) = text.strip_prefix("1]") {
        ("INPV1".to_string(), rest.trim())
    } else {
        return Err(DecryptionError::plain(
            "فایل معتبر NPVT/INPV نیست (شناسه NPVT1، NPVTSUB1 یا 1] یافت نشد).",
        ));
    };

    let sep = if kind == "INPV1" { ']' } else { ',' };
    let parts: Vec<&str> = body.split(sep).collect();
    if parts.is_empty() || parts[0].trim().is_empty() {
        return Err(DecryptionError::plain("ساختار پی‌لود NPVT ناقص است."));
    }

    let mut version = 1;
    let server_payload = if parts.len() > 1 {
        parts[1].trim()
    } else {
        parts[0].trim()
    };

    if kind != "INPV1" && parts.len() > 1 {
        if let Ok(v_str) = decrypt_payload(parts[0].trim()) {
            if let Ok(v) = v_str.trim().parse::<i32>() {
                if v != 0 {
                    version = v;
                }
            }
        }
    }

    let mut parsed: Option<Value> = None;
    if let Ok(dec) = decrypt_payload(server_payload) {
        if let Ok(val) = serde_json::from_str::<Value>(&dec) {
            parsed = Some(val);
        }
    }

    if parsed.is_none() && kind == "INPV1" && parts.len() > 1 {
        if let Ok(dec2) = decrypt_payload(parts[0].trim()) {
            if let Ok(val2) = serde_json::from_str::<Value>(&dec2) {
                parsed = Some(val2);
            }
        }
    }

    let parsed_val = parsed.ok_or_else(|| {
        DecryptionError::plain("رمزگشایی فایل NPVT ناموفق بود یا داده خروجی JSON معتبر نیست.")
    })?;

    let mut settings = None;
    if parts.len() >= 3 && !parts[2].trim().is_empty() {
        if let Ok(dec_settings) = decrypt_payload(parts[2].trim()) {
            if let Ok(sv) = serde_json::from_str::<Value>(&dec_settings) {
                settings = Some(sv);
            }
        }
    }

    let profiles = match parsed_val {
        Value::Array(arr) => arr,
        Value::Object(ref map) => {
            if let Some(Value::Array(cfgs)) = map.get("configs") {
                cfgs.clone()
            } else {
                vec![parsed_val]
            }
        }
        other => vec![other],
    };

    Ok(NpvtDecoded {
        kind,
        version,
        profiles,
        settings,
    })
}
