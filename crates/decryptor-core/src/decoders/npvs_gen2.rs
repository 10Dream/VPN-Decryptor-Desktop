use crate::crypto_utils::{
    base64_decode_safe, chacha20_poly1305_open, hkdf_sha256, inflate_zlib, pbkdf2_hmac_sha256,
};
use crate::decoders::npvs::NpvsDecoded;
use crate::decoders::npvs_gen2_sub7dc0::gen2_sub7dc0;
use crate::models::DecryptionError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

static GEN2_TABLES_ZLIB: &[u8] = include_bytes!("../../assets/npvs_gen2_tables.zlib");

const ENVELOPE_VERSION: u8 = 5;
const HEADER_FIXED: usize = 135;
const KEY_BLOCK_OFFSET: usize = 53;
const SENTINEL_SEQ: u16 = 0xffff;
const METHOD_RECIPIENT: u8 = 0;
const METHOD_PASS: u8 = 1;
const METHOD_APPKEY: u8 = 2;
const RECIPIENT_PK_SIZE: usize = 32;
const RECIPIENT_WRAP_SIZE: usize = 0x5d;
const PASS_BLOCK_SIZE: usize = 80;
const APPKEY_BLOCK_SIZE: usize = 78;
const SIG_SIZE: usize = 64;

const METADATA_INFO: &[u8] = b"NPVS-v5/metadata";
const FIELD_KEY_INFO: &[u8] = b"NPV-fields-v1/field/";
const RECORD_AAD_INFO: &[u8] = b"NPV-fields-v1/record/";
const BODY_MAGIC: &[u8; 4] = b"NPF\x01";
const GEN2_APPKEY_LABEL: &[u8] = b"npvtunnel/appkey/v2 ";

const GEN2_BLOCK_SIZE: usize = 57344;
const GEN2_BLOCK_COUNT: usize = 13;
const GEN2_PAGE_SIZE: usize = 4096;
const GEN2_TABLES_SIZE: usize = GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE + GEN2_PAGE_SIZE;
const GEN2_SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

static GEN2_TABLES: OnceLock<Vec<u8>> = OnceLock::new();

fn gen2_tables() -> &'static [u8] {
    GEN2_TABLES.get_or_init(|| {
        let raw = inflate_zlib(GEN2_TABLES_ZLIB).expect("Corrupt Gen2 whitebox tables");
        assert_eq!(raw.len(), GEN2_TABLES_SIZE, "Unexpected Gen2 whitebox size");
        raw
    })
}

fn decode_sentinels(str_val: &str) -> String {
    if let Some(rest) = str_val.strip_prefix("npvs1:") {
        if let Ok(bytes) = base64_decode_safe(rest) {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
        return str_val.to_string();
    }

    const SENTINEL_PREFIX: &str = "npv1:";
    const ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";
    let mut out = String::new();
    let mut i = 0;
    while i < str_val.len() {
        if str_val[i..].starts_with(SENTINEL_PREFIX) {
            i += SENTINEL_PREFIX.len();
            let mut acc: u32 = 0;
            let mut count = 0;
            while i < str_val.len() && count < 3 {
                let ch = str_val[i..].chars().next().unwrap();
                if let Some(idx) = ALPHABET.find(ch) {
                    acc = acc * 68 + idx as u32;
                    count += 1;
                    i += ch.len_utf8();
                } else {
                    break;
                }
            }
            if let Some(decoded_char) = char::from_u32(acc & 0xffff) {
                out.push(decoded_char);
            }
        } else {
            let ch = str_val[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[inline]
fn be32(block: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]])
}

#[inline]
fn group_args(block: &[u8], half: usize, j: usize, s: [u8; 4]) -> (u32, u32, u32, u32) {
    let base = half + 0x1000 * j;
    (
        be32(block, base + 4 * s[0] as usize),
        be32(block, base + 0x400 + 4 * s[1] as usize),
        be32(block, base + 0x800 + 4 * s[2] as usize),
        be32(block, base + 0xc00 + 4 * s[3] as usize),
    )
}

#[inline]
fn shift_state(state: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = state[GEN2_SHIFT_ROWS[i]];
    }
    out
}

pub fn gen2_a16(salt: &[u8]) -> Result<[u8; 16], String> {
    if salt.len() != 16 {
        return Err(format!("Gen2 salt must be 16 bytes, got {}", salt.len()));
    }
    let tables = gen2_tables();
    let mut state = [0u8; 16];
    state.copy_from_slice(salt);

    for b in 0..GEN2_BLOCK_COUNT {
        let block = &tables[b * GEN2_BLOCK_SIZE..(b + 1) * GEN2_BLOCK_SIZE];
        state = shift_state(&state);
        for j in 0..4 {
            let mut s = [state[4 * j], state[4 * j + 1], state[4 * j + 2], state[4 * j + 3]];
            let (a, bb, c, d) = group_args(block, 0x6000, j, s);
            s = gen2_sub7dc0(block, j as u32, a, bb, c, d);
            let (a2, b2, c2, d2) = group_args(block, 0xa000, j, s);
            s = gen2_sub7dc0(block, j as u32, a2, b2, c2, d2);
            state[4 * j..4 * j + 4].copy_from_slice(&s);
        }
    }

    let page = &tables[GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE..];
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = page[0x100 * i + state[GEN2_SHIFT_ROWS[i]] as usize];
    }
    Ok(out)
}

fn gen2_kdk(a16: &[u8; 16], config_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GEN2_APPKEY_LABEL);
    hasher.update(a16);
    hasher.update(config_id);
    let dig = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

struct Gen2Envelope<'a> {
    config_id: &'a [u8],
    method: u8,
    iters: u32,
    salt: &'a [u8],
    wrap: &'a [u8],
    prefix: &'a [u8],
    meta_blob: &'a [u8],
    nonce: &'a [u8],
    body: &'a [u8],
}

fn parse_gen2_envelope(data: &[u8]) -> Result<Gen2Envelope<'_>, DecryptionError> {
    if data.len() < 9 || &data[0..4] != b"NPVS" || data[4] != ENVELOPE_VERSION {
        return Err(DecryptionError::plain("پاکت فشردهٔ نسخهٔ ۵ نیست."));
    }
    let hdr_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if hdr_len < HEADER_FIXED || 9 + hdr_len > data.len() {
        return Err(DecryptionError::plain(format!("طول سرآیند نامعتبر: {}", hdr_len)));
    }
    let h = &data[9..9 + hdr_len];
    if h[0] != 1 {
        return Err(DecryptionError::plain(format!("نسخه سرآیند پشتیبانی نمی‌شود: {}", h[0])));
    }
    let config_id = &h[1..17];
    let method = h[50];
    if ![METHOD_RECIPIENT, METHOD_PASS, METHOD_APPKEY].contains(&method) {
        return Err(DecryptionError::plain(format!("روش باز کردن ناشناخته: {}", method)));
    }
    let recipients = u16::from_be_bytes([h[51], h[52]]) as usize;
    let mut off = KEY_BLOCK_OFFSET + recipients * (RECIPIENT_PK_SIZE + RECIPIENT_WRAP_SIZE);

    let (iters, salt, wrap) = if method == METHOD_PASS {
        if off + PASS_BLOCK_SIZE + 4 > h.len() {
            return Err(DecryptionError::plain("هدر پسورد ناقص است."));
        }
        let iters = u32::from_be_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]);
        let salt = &h[off + 4..off + 20];
        let wrap = &h[off + 20..off + PASS_BLOCK_SIZE];
        off += PASS_BLOCK_SIZE;
        (iters, salt, wrap)
    } else if method == METHOD_APPKEY {
        if off + APPKEY_BLOCK_SIZE + 4 > h.len() {
            return Err(DecryptionError::plain("هدر کلید برنامه ناقص است."));
        }
        let salt = &h[off + 2..off + 18];
        let wrap = &h[off + 18..off + APPKEY_BLOCK_SIZE];
        off += APPKEY_BLOCK_SIZE;
        (0, salt, wrap)
    } else {
        return Err(DecryptionError::plain("روش باز کردن Recipient پشتیبانی نمی‌شود."));
    };

    let meta_len = u32::from_be_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]) as usize;
    let prefix = &h[0..off];
    if off + 4 + meta_len > h.len() {
        return Err(DecryptionError::plain("متاباب نامعتبر در سرآیند نسخه ۵."));
    }
    let meta_blob = &h[off + 4..off + 4 + meta_len];

    let body_off = 9 + hdr_len;
    if body_off + 16 > data.len() {
        return Err(DecryptionError::plain("بخش بدنه فایل نسخه ۵ ناقص است."));
    }
    let nonce = &data[body_off..body_off + 12];
    let body_len = u32::from_be_bytes([
        data[body_off + 12],
        data[body_off + 13],
        data[body_off + 14],
        data[body_off + 15],
    ]) as usize;
    let start = body_off + 16;
    if start + body_len + SIG_SIZE > data.len() {
        return Err(DecryptionError::plain("طول بدنه فایل نسخه ۵ نامعتبر است."));
    }
    let body = &data[start..start + body_len];

    Ok(Gen2Envelope {
        config_id,
        method,
        iters,
        salt,
        wrap,
        prefix,
        meta_blob,
        nonce,
        body,
    })
}

fn gen2_open(env: &Gen2Envelope<'_>, password: &str) -> Result<(Vec<u8>, Vec<u8>), DecryptionError> {
    if env.method == METHOD_APPKEY {
        let a16 = gen2_a16(env.salt).map_err(DecryptionError::plain)?;
        let kdk = gen2_kdk(&a16, env.config_id);
        let dek = chacha20_poly1305_open(&kdk, &env.wrap[0..12], &env.wrap[12..], env.salt)
            .map_err(|_| DecryptionError::plain("بازگشایی کلید برنامه (AppKey) با شکست مواجه شد."))?;
        let meta_key = hkdf_sha256(&dek, env.nonce, METADATA_INFO);
        let metadata = chacha20_poly1305_open(&meta_key, env.nonce, env.meta_blob, env.prefix)
            .map_err(|_| DecryptionError::plain("متاباب مهرشده باز نشد."))?;
        Ok((dek, metadata))
    } else if env.method == METHOD_PASS {
        if password.trim().is_empty() {
            return Err(DecryptionError::needs_password(
                "برای باز کردن این فایل نسخهٔ ۵ به رمز عبور نیاز است",
                None,
            ));
        }

        let raw_p = password.trim();
        let alt_at = if let Some(rest) = raw_p.strip_prefix('@') {
            rest.to_string()
        } else {
            format!("@{}", raw_p)
        };
        let lower_p = raw_p.to_lowercase();
        let mut seen = HashSet::new();
        let mut cands = Vec::new();
        for c in [raw_p.to_string(), alt_at, lower_p] {
            if !c.is_empty() && seen.insert(c.clone()) {
                cands.push(c);
            }
        }

        for cand in cands {
            let kdk = pbkdf2_hmac_sha256(cand.as_bytes(), env.salt, env.iters);
            if let Ok(dek) =
                chacha20_poly1305_open(&kdk, &env.wrap[0..12], &env.wrap[12..], env.salt)
            {
                let meta_key = hkdf_sha256(&dek, env.nonce, METADATA_INFO);
                if let Ok(metadata) =
                    chacha20_poly1305_open(&meta_key, env.nonce, env.meta_blob, env.prefix)
                {
                    return Ok((dek, metadata));
                }
            }
        }

        Err(DecryptionError::invalid_password(
            "رمز عبور وارد شده برای این فایل نادرست است.",
        ))
    } else {
        Err(DecryptionError::plain(format!(
            "روش باز کردن {} پشتیبانی نمی‌شود.",
            env.method
        )))
    }
}

fn decrypt_gen2_fields(env: &Gen2Envelope<'_>, dek: &[u8]) -> Result<BTreeMap<u16, Vec<u8>>, DecryptionError> {
    let body = env.body;
    if body.len() < 66 || &body[0..4] != BODY_MAGIC {
        return Err(DecryptionError::plain("بدنهٔ NPF نامعتبر است."));
    }
    let content_id = &body[4..36];
    let count = u16::from_be_bytes([body[36], body[37]]) as usize;
    let mut off = 38usize;
    let mut fields = BTreeMap::new();
    let zero_nonce = [0u8; 12];

    for _ in 0..count {
        if off + 6 > body.len() {
            break;
        }
        let seq = u16::from_be_bytes([body[off], body[off + 1]]);
        let blob_len = u16::from_be_bytes([body[off + 4], body[off + 5]]) as usize;
        off += 6;
        if off + blob_len > body.len() {
            break;
        }
        let blob = &body[off..off + blob_len];
        off += blob_len;
        if blob.len() < 16 {
            continue;
        }
        let pt_len = (blob.len() - 16) as u32;
        let seq_bytes = seq.to_be_bytes();

        let mut info = Vec::with_capacity(FIELD_KEY_INFO.len() + 2);
        info.extend_from_slice(FIELD_KEY_INFO);
        info.extend_from_slice(&seq_bytes);
        let key = hkdf_sha256(dek, content_id, &info);

        let mut aad = Vec::with_capacity(RECORD_AAD_INFO.len() + 32 + 2 + 4);
        aad.extend_from_slice(RECORD_AAD_INFO);
        aad.extend_from_slice(content_id);
        aad.extend_from_slice(&seq_bytes);
        aad.extend_from_slice(&pt_len.to_be_bytes());

        if let Ok(pt) = chacha20_poly1305_open(&key, &zero_nonce, blob, &aad) {
            fields.insert(seq, pt);
        }
    }
    Ok(fields)
}

fn field_text(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw).trim().to_string();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        if let Ok(Value::String(unquoted)) = serde_json::from_str::<Value>(&s) {
            return unquoted;
        }
        return s[1..s.len() - 1].to_string();
    }
    s
}

fn substitute_value(v: Value, fields: &BTreeMap<u16, Vec<u8>>) -> Value {
    match v {
        Value::Bool(b) => Value::Bool(b),
        Value::Number(num) => {
            if let Some(seq_i) = num.as_u64() {
                if let Ok(seq) = u16::try_from(seq_i) {
                    if let Some(raw) = fields.get(&seq) {
                        return Value::String(decode_sentinels(&field_text(raw)));
                    }
                    return Value::String(String::new());
                }
            }
            Value::Number(num)
        }
        Value::Array(arr) => {
            Value::Array(arr.into_iter().map(|el| substitute_value(el, fields)).collect())
        }
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, val) in map {
                out.insert(k, substitute_value(val, fields));
            }
            Value::Object(out)
        }
        other => other,
    }
}

pub fn decrypt_npvs_gen2(data: &[u8], password: &str) -> Result<NpvsDecoded, DecryptionError> {
    let env = parse_gen2_envelope(data)?;
    let (dek, metadata) = gen2_open(&env, password)?;
    let fields = decrypt_gen2_fields(&env, &dek)?;

    let configs: Vec<Value> = if let Some(table) = fields.get(&SENTINEL_SEQ) {
        let spec: Value = serde_json::from_slice(table)
            .map_err(|e| DecryptionError::plain(format!("خطا در پارس جدول فیلدهای نسخه ۵: {}", e)))?;
        match spec.get("configs").and_then(|c| c.as_array()) {
            Some(arr) => arr.iter().cloned().map(|c| substitute_value(c, &fields)).collect(),
            None => Vec::new(),
        }
    } else {
        fields
            .iter()
            .filter(|(&seq, _)| seq != SENTINEL_SEQ)
            .map(|(&seq, raw)| {
                serde_json::json!({
                    "seq": seq,
                    "text": String::from_utf8_lossy(raw)
                })
            })
            .collect()
    };

    let meta_json: Option<Value> = serde_json::from_slice(&metadata).ok();
    let policy = meta_json
        .as_ref()
        .and_then(|m| m.get("policy"))
        .cloned()
        .unwrap_or(Value::Null);

    Ok(NpvsDecoded {
        version: ENVELOPE_VERSION,
        config_id: hex::encode(env.config_id),
        used_method: "wbaes-ctr-sha256-gen2".to_string(),
        policy,
        profiles: configs,
    })
}
