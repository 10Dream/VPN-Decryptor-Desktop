use aes::cipher::{BlockDecrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::{aead::Aead as AeadGcm, aead::Payload, Aes256Gcm, Key as GcmKey, Nonce as GcmNonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use cbc::Decryptor as CbcDecryptor;
use cfb_mode::Decryptor as CfbDecryptor;
use chacha20::cipher::{KeyIvInit as ChaChaKeyIvInit, StreamCipher as ChaChaStreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20Legacy};
use chacha20poly1305::{ChaCha20Poly1305, Key as PolyKey, Nonce as PolyNonce};
use ecb::Decryptor as EcbDecryptor;
use flate2::read::ZlibDecoder;
use hmac::Hmac;
use sha2::Sha256;
use std::io::Read;

use aes::{Aes128, Aes192, Aes256};

/// Decode Base64 or Base64URL string safely, stripping whitespace and adding padding.
pub fn base64_decode_safe(input: &str) -> Result<Vec<u8>, String> {
    let mut cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while cleaned.len() % 4 != 0 {
        cleaned.push('=');
    }
    STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| format!("Invalid Base64: {}", e))
}

pub fn base64_url_encode_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn base64_encode_std(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let rem = cleaned.len() % 4;
    if rem != 0 {
        for _ in 0..(4 - rem) {
            cleaned.push('=');
        }
    }
    STANDARD
        .decode(cleaned.as_bytes())
        .or_else(|_| URL_SAFE.decode(input.trim()))
        .map_err(|e| format!("Base64Url decode error: {}", e))
}

pub fn pkcs7_unpad(data: &[u8], block_size: usize, strict: bool) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad = *data.last().unwrap() as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        if strict {
            return Err("Invalid PKCS7 padding length".to_string());
        }
        return Ok(data.to_vec());
    }
    let start = data.len() - pad;
    if data[start..].iter().all(|&b| b as usize == pad) {
        Ok(data[..start].to_vec())
    } else if strict {
        Err("Invalid PKCS7 padding bytes".to_string())
    } else {
        Ok(data.to_vec())
    }
}

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8], unpad: bool) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("Ciphertext length must be a non-zero multiple of 16 for AES-ECB".to_string());
    }
    let mut buf = ciphertext.to_vec();
    match key.len() {
        16 => {
            let cipher = EcbDecryptor::<Aes128>::new_from_slice(key)
                .map_err(|e| format!("AES-128 key error: {}", e))?;
            for chunk in buf.chunks_exact_mut(16) {
                cipher.decrypt_block_mut(chunk.into());
            }
        }
        24 => {
            let cipher = EcbDecryptor::<Aes192>::new_from_slice(key)
                .map_err(|e| format!("AES-192 key error: {}", e))?;
            for chunk in buf.chunks_exact_mut(16) {
                cipher.decrypt_block_mut(chunk.into());
            }
        }
        32 => {
            let cipher = EcbDecryptor::<Aes256>::new_from_slice(key)
                .map_err(|e| format!("AES-256 key error: {}", e))?;
            for chunk in buf.chunks_exact_mut(16) {
                cipher.decrypt_block_mut(chunk.into());
            }
        }
        _ => return Err("Unsupported AES key size for ECB".to_string()),
    }
    if unpad {
        pkcs7_unpad(&buf, 16, false)
    } else {
        Ok(buf)
    }
}

pub fn decrypt_aes_cbc_nopad(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || iv.len() != 16 {
        return Err("Invalid AES-CBC input length".to_string());
    }
    let mut buf = ciphertext.to_vec();
    match key.len() {
        16 => {
            let dec = CbcDecryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|e| format!("AES-128-CBC init error: {}", e))?;
            use aes::cipher::BlockDecryptMut;
            let mut prev = [0u8; 16];
            prev.copy_from_slice(iv);
            let _ = dec; // Use block-by-block CBC cleanly with Aes128
            let cipher = Aes128::new_from_slice(key).unwrap();
            for chunk in buf.chunks_exact_mut(16) {
                let mut saved = [0u8; 16];
                saved.copy_from_slice(chunk);
                cipher.decrypt_block(chunk.into());
                for i in 0..16 {
                    chunk[i] ^= prev[i];
                }
                prev = saved;
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|e| format!("AES-256 init error: {}", e))?;
            let mut prev = [0u8; 16];
            prev.copy_from_slice(iv);
            for chunk in buf.chunks_exact_mut(16) {
                let mut saved = [0u8; 16];
                saved.copy_from_slice(chunk);
                cipher.decrypt_block(chunk.into());
                for i in 0..16 {
                    chunk[i] ^= prev[i];
                }
                prev = saved;
            }
        }
        _ => return Err("Unsupported AES key length for CBC".to_string()),
    }
    Ok(buf)
}

/// Decrypt AES-CFB-128 (OpenSSL / Node crypto `aes-192-cfb` / `aes-256-cfb` default = full-block CFB128).
pub fn decrypt_aes_cfb(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if iv.len() != 16 {
        return Err("AES-CFB IV must be 16 bytes".to_string());
    }
    let mut buf = ciphertext.to_vec();
    match key.len() {
        16 => {
            let dec = CfbDecryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|e| format!("AES-128-CFB init: {}", e))?;
            dec.decrypt(&mut buf);
        }
        24 => {
            let dec = CfbDecryptor::<Aes192>::new_from_slices(key, iv)
                .map_err(|e| format!("AES-192-CFB init: {}", e))?;
            dec.decrypt(&mut buf);
        }
        32 => {
            let dec = CfbDecryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|e| format!("AES-256-CFB init: {}", e))?;
            dec.decrypt(&mut buf);
        }
        _ => return Err("Unsupported AES key length for CFB".to_string()),
    }
    Ok(buf)
}

pub fn decrypt_aes_256_gcm(key: &[u8], iv: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 || iv.len() != 12 || tag.len() != 16 {
        return Err("Invalid AES-256-GCM parameters".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut combined = Vec::with_capacity(ct.len() + tag.len());
    combined.extend_from_slice(ct);
    combined.extend_from_slice(tag);
    cipher
        .decrypt(GcmNonce::from_slice(iv), combined.as_slice())
        .map_err(|_| "AES-256-GCM authentication failed".to_string())
}

pub fn chacha20_poly1305_open(
    key: &[u8],
    nonce: &[u8],
    ct_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 || nonce.len() != 12 || ct_and_tag.len() < 16 {
        return Err("Invalid ChaCha20-Poly1305 parameters".to_string());
    }
    let cipher = ChaCha20Poly1305::new(PolyKey::from_slice(key));
    cipher
        .decrypt(
            PolyNonce::from_slice(nonce),
            Payload {
                msg: ct_and_tag,
                aad,
            },
        )
        .map_err(|_| "ChaCha20-Poly1305 authentication failed".to_string())
}

/// Legacy DJB ChaCha20 with 8-byte nonce and 64-bit block counter (matches PyCryptodome / SSC / HTTP Custom).
pub fn chacha20_legacy_xor(key: &[u8], nonce8: &[u8], data: &[u8], initial_counter: u64) -> Result<Vec<u8>, String> {
    if key.len() != 32 || nonce8.len() != 8 {
        return Err("ChaCha20 legacy requires 32-byte key and 8-byte nonce".to_string());
    }
    let mut cipher = ChaCha20Legacy::new_from_slices(key, nonce8)
        .map_err(|e| format!("ChaCha20 init error: {}", e))?;
    cipher.seek(initial_counter * 64);
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut out)
        .expect("PBKDF2-HMAC-SHA256 derivation failed");
    out
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = hkdf::Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand failed");
    okm
}

pub fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("Zlib inflate failed: {}", e))?;
    Ok(out)
}

pub fn decode_utf8_lossy_or_latin1(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
