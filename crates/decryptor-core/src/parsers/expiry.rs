use crate::models::ExpiryInfo;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde_json::Value;

pub fn check_expiration_str(raw_opt: Option<&str>) -> ExpiryInfo {
    let Some(raw) = raw_opt else {
        return ExpiryInfo::default();
    };
    let s = raw.trim();
    if s.is_empty() || s == "0" || s == "null" {
        return ExpiryInfo::default();
    }

    let dt_opt: Option<DateTime<Utc>> = if s.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(mut num) = s.parse::<i64>() {
            if num <= 0 {
                return ExpiryInfo::default();
            }
            if num < 100_000_000_000 {
                num *= 1000;
            }
            DateTime::from_timestamp_millis(num)
        } else {
            None
        }
    } else if let Ok(rfc) = DateTime::parse_from_rfc3339(s) {
        Some(rfc.with_timezone(&Utc))
    } else if let Ok(rfc2822) = DateTime::parse_from_rfc2822(s) {
        Some(rfc2822.with_timezone(&Utc))
    } else if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y/%m/%d %H:%M:%S"))
    {
        Some(ndt.and_utc())
    } else if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .or_else(|_| NaiveDate::parse_from_str(s, "%Y/%m/%d"))
    {
        nd.and_hms_opt(0, 0, 0).map(|ndt| ndt.and_utc())
    } else {
        None
    };

    let Some(exp_dt) = dt_opt else {
        return ExpiryInfo::default();
    };

    let now = Utc::now();
    let is_expired = exp_dt < now;
    ExpiryInfo {
        has_expiry: true,
        is_expired,
        formatted: Some(exp_dt.format("%Y-%m-%d %H:%M:%S").to_string()),
    }
}

pub fn check_expiration_json(val: &Value) -> ExpiryInfo {
    let raw = extract_expiry_str_from_json(val);
    check_expiration_str(raw.as_deref())
}

pub fn extract_expiry_str_from_json(val: &Value) -> Option<String> {
    fn as_nonempty(v: &Value) -> Option<String> {
        match v {
            Value::String(s) if !s.trim().is_empty() && s.trim() != "0" && s.trim() != "null" => {
                Some(s.trim().to_string())
            }
            Value::Number(n) if n.as_i64().unwrap_or(0) > 0 => Some(n.to_string()),
            _ => None,
        }
    }

    let obj = val.as_object()?;
    let paths: &[&[&str]] = &[
        &["settings", "expiryDate"],
        &["settings", "expiresAt"],
        &["settings", "expiryTime"],
        &["settings", "policy", "expiresAt"],
        &["policy", "expiresAt"],
        &["expiresAt"],
        &["expiryDate"],
        &["expiryTime"],
        &["Expiration Date"],
        &["fields", "expiryTime"],
        &["fields", "expiryDate"],
        &["fields", "EXPIRY_DATE"],
        &["fields", "Expiration Date"],
        &["parsed", "ExpiredDate"],
        &["parsed", "Expired Date"],
        &["parsed", "protextras", "expiry_value"],
        &["configExpiryTimestamp"],
        &["parsed", "configExpiryTimestamp"],
        &["fields", "configExpiryTimestamp"],
        &["settings", "configExpiryTimestamp"],
    ];

    for p in paths {
        let mut cur = val;
        let mut found = true;
        for &seg in *p {
            if let Some(next) = cur.get(seg) {
                cur = next;
            } else {
                found = false;
                break;
            }
        }
        if found {
            if let Some(res) = as_nonempty(cur) {
                return Some(res);
            }
        }
    }
    let _ = obj;
    None
}
