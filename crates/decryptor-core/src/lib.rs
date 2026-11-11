pub mod builders;
pub mod crypto_utils;
pub mod decoders;
pub mod http_client;
pub mod models;
pub mod parsers;
pub mod pipeline;
pub mod sanitizer;

pub fn version() -> &'static str {
    "1.0.0"
}

#[cfg(test)]
mod tests {
    use crate::builders::mihomo::build_mihomo_config;
    use crate::builders::singbox::build_singbox_config;
    use crate::builders::xray::{build_xray_base64, build_xray_links};
    use crate::decoders::dark::decrypt_dark;
    use crate::decoders::ehi::decrypt_ehi_xor_field;
    use crate::decoders::httpcustom::process_hc_credentials;
    use crate::decoders::npvt::decrypt_npvt;
    use crate::models::{ProxyMode, ProxyProfile, ALL_SUPPORTED_PROTOCOLS};
    use crate::parsers::expiry::check_expiration_str;
    use crate::parsers::mihomo::parse_mihomo_yaml;
    use crate::parsers::singbox::parse_singbox_json;
    use crate::parsers::subscription::{
        normalize_subscription_url, parse_amnezia_vpn_uri, parse_anytls_uri, parse_naive_uri,
        parse_subscription_text, parse_uri_config, split_concatenated_links,
    };
    use crate::parsers::wireguard::parse_wireguard_conf;
    use crate::pipeline::extract_filename_password_hints;
    use crate::sanitizer::filter_and_deduplicate_with_stats;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn test_protocol_count_and_names() {
        assert_eq!(ALL_SUPPORTED_PROTOCOLS.len(), 26);
        assert!(ALL_SUPPORTED_PROTOCOLS.contains(&"VLESS"));
        assert!(ALL_SUPPORTED_PROTOCOLS.contains(&"ANYTLS"));
        assert!(ALL_SUPPORTED_PROTOCOLS.contains(&"NAIVE"));
    }

    #[test]
    fn test_uri_splitting_and_parsing() {
        let glued = "vless://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:443?type=ws&security=tls&sni=example.com#FirstNode\
                     trojan://secretpass@5.6.7.8:443?sni=trojan.example.com#SecondNode\
                     hy2://hypass@9.10.11.12:8443?sni=hy.example.com&obfs=salamander&obfs-password=obfpw#HyNode";
        let links = split_concatenated_links(glued);
        assert_eq!(links.len(), 3, "Expected 3 glued links split cleanly");

        let p1 = parse_uri_config(&links[0]).expect("VLESS must parse");
        assert_eq!(p1.protocol, "vless");
        assert_eq!(p1.server, "1.2.3.4");
        assert_eq!(p1.server_port, 443);
        assert!(p1.tls);

        let p2 = parse_uri_config(&links[1]).expect("Trojan must parse");
        assert_eq!(p2.protocol, "trojan");
        assert_eq!(p2.password, "secretpass");

        let p3 = parse_uri_config(&links[2]).expect("Hy2 must parse");
        assert_eq!(p3.protocol, "hysteria2");
        assert_eq!(p3.obfs, "salamander");
        assert_eq!(p3.obfs_password, "obfpw");
    }

    #[test]
    fn test_anytls_naive_and_amnezia_vpn() {
        let any = parse_anytls_uri("anytls://mypass@any.example.com:8443?sni=any.example.com&insecure=1#Any1")
            .expect("AnyTLS must parse");
        assert_eq!(any.protocol, "anytls");
        assert_eq!(any.password, "mypass");
        assert!(any.skip_cert_verify);

        let nv = parse_naive_uri("naive+https://user1:pass1@nv.example.com:443?sni=nv.example.com#Naive1")
            .expect("Naive must parse");
        assert_eq!(nv.protocol, "naive");
        assert_eq!(nv.username, "user1");
        assert_eq!(nv.password, "pass1");

        // Amnezia vpn:// payload with zlib JSON
        let wg_json = serde_json::json!({
            "containers": [{
                "container": "amnezia-awg",
                "awg": {
                    "last_config": "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = 185.10.20.30:51820\n"
                }
            }],
            "description": "AmneziaTest"
        });
        let raw_json = serde_json::to_vec(&wg_json).unwrap();
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw_json).unwrap();
        let compressed = enc.finish().unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&(raw_json.len() as u32).to_be_bytes());
        blob.extend_from_slice(&compressed);
        let b64_u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&blob);
        let amz = parse_amnezia_vpn_uri(&format!("vpn://{}", b64_u));
        assert_eq!(amz.len(), 1);
        assert_eq!(amz[0].protocol, "wireguard");
        assert_eq!(amz[0].server, "185.10.20.30");
        assert!(amz[0].amnezia_options.is_some());
    }

    #[test]
    fn test_sanitizer_dedup_and_builders() {
        let profiles = vec![
            ProxyProfile {
                protocol: "vless".into(),
                name: "Node-A".into(),
                server: "104.20.1.1".into(),
                server_port: 443,
                uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
                encryption: "mlkem768x25519plus.native.0rtt.TEST".into(),
                network: "xhttp".into(),
                path: "/xhttp-path".into(),
                host: "cdn.example.com".into(),
                tls: true,
                sni: "cdn.example.com".into(),
                fingerprint: "chrome".into(),
                ..Default::default()
            },
            // Exact duplicate connection with different remark name
            ProxyProfile {
                protocol: "vless".into(),
                name: "Node-A-Duplicate".into(),
                server: "104.20.1.1".into(),
                server_port: 443,
                uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
                encryption: "mlkem768x25519plus.native.0rtt.TEST".into(),
                network: "xhttp".into(),
                path: "/xhttp-path".into(),
                host: "cdn.example.com".into(),
                tls: true,
                sni: "cdn.example.com".into(),
                fingerprint: "chrome".into(),
                ..Default::default()
            },
            // Fake Iranian domain HTTP proxy should be filtered as broken
            ProxyProfile {
                protocol: "http".into(),
                name: "FakeSite".into(),
                server: "digikala.com".into(),
                server_port: 443,
                ..Default::default()
            },
        ];

        let (valid, stats) = filter_and_deduplicate_with_stats(&profiles, true, true);
        assert_eq!(valid.len(), 1);
        assert_eq!(stats.duplicates, 1);
        assert_eq!(stats.rejected, 1);

        let xray = build_xray_links(&valid, true, true, false);
        assert!(xray.starts_with("vless://550e8400"));
        assert!(xray.contains("encryption=mlkem768"));
        assert!(!build_xray_base64(&xray).is_empty());

        let mihomo = build_mihomo_config(&valid, true, true, false);
        assert!(mihomo.contains("xhttp-opts:"));
        assert!(mihomo.contains("encryption: \"mlkem768x25519plus.native.0rtt.TEST\""));

        let sb = build_singbox_config(&valid, true, true, false);
        let parsed_sb: serde_json::Value = serde_json::from_str(&sb).unwrap();
        assert!(parsed_sb["outbounds"].as_array().unwrap().len() >= 6);
    }

    #[test]
    fn test_wireguard_mihomo_singbox_roundtrip() {
        let wg_conf = r#"
[Interface]
PrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Address = 10.7.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 162.159.192.1:2408
"#;
        let prof = parse_wireguard_conf(wg_conf, "warp.conf").expect("WG conf must parse");
        assert_eq!(prof.protocol, "wireguard");
        assert_eq!(prof.server, "162.159.192.1");
        assert_eq!(prof.server_port, 2408);

        let yaml = build_mihomo_config(&[prof.clone()], false, false, true);
        let (parsed_mh, _prov) = parse_mihomo_yaml(&yaml).expect("Generated Mihomo YAML must parse");
        assert_eq!(parsed_mh.len(), 1);
        assert_eq!(parsed_mh[0].protocol, "wireguard");

        let sb_json = build_singbox_config(&[prof], false, false, true);
        let parsed_sb = parse_singbox_json(&sb_json, "wg.json").expect("Generated Sing-box must parse");
        assert_eq!(parsed_sb.len(), 1);
        assert_eq!(parsed_sb[0].protocol, "wireguard");
    }

    #[test]
    fn test_url_normalization_expiry_and_password_hints() {
        assert_eq!(
            normalize_subscription_url("https://github.com/user/repo/blob/main/sub.txt"),
            "https://raw.githubusercontent.com/user/repo/main/sub.txt"
        );
        let past = check_expiration_str(Some("2020-01-01 00:00:00"));
        assert!(past.has_expiry && past.is_expired);

        let future = check_expiration_str(Some("2099-01-01 00:00:00"));
        assert!(future.has_expiry && !future.is_expired);

        let hints = extract_filename_password_hints("Free_@MyChannel_VIP.npvs");
        assert!(hints.contains(&"@MyChannel".to_string()));
        assert!(hints.contains(&"mychannel".to_string()));
    }

    #[test]
    fn test_subscription_base64_and_invalid_decoder_graceful() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let raw_sub = "vless://550e8400-e29b-41d4-a716-446655440000@8.8.8.8:443?security=none#B64Test";
        let b64 = STANDARD.encode(raw_sub.as_bytes());
        let res = rt
            .block_on(parse_subscription_text(&b64, &ProxyMode::DirectOnly, ""))
            .expect("Base64 sub should decode");
        assert_eq!(res.profiles.len(), 1);
        assert_eq!(res.profiles[0].server, "8.8.8.8");

        assert!(decrypt_npvt("NOT_NPVT").is_err());
        assert!(decrypt_dark("not_b64").is_err());
        assert_eq!(decrypt_ehi_xor_field("", "EVZJNI"), "");
        assert_eq!(process_hc_credentials("", true), "");
    }

    #[test]
    fn test_mihomo_template_http_opts_and_encryption_guard() {
        let http_vless = ProxyProfile {
            protocol: "vless".into(),
            name: "HttpNode".into(),
            server: "1.1.1.1".into(),
            server_port: 80,
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            encryption: "reality".into(), // bogus value that must not be emitted
            network: "http".into(),
            path: "/api".into(),
            host: "cdn.test.org".into(),
            ..Default::default()
        };
        let yaml = build_mihomo_config(&[http_vless], true, true, false);
        assert_eq!(yaml.matches("\nproxies:\n").count(), 1);
        assert!(!yaml.contains("__PROXY_SLOT__"));
        assert!(!yaml.contains("__PROXIES_PLACEHOLDER__"));
        assert!(yaml.contains("path: [\"/api\"]"));
        assert!(yaml.contains("        Host:\n          - \"cdn.test.org\""));
        assert!(!yaml.contains("encryption: \"reality\""));
        assert!(yaml.contains("      - \"HttpNode\""));
    }

    #[test]
    fn test_shadowsocks_2022_percent_colon_and_corrupt_cipher_cleanup() {
        let ss_link = "ss://2022-blake3-aes-256-gcm:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=%3AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=@8.8.4.4:8388#SS2022";
        let prof = parse_uri_config(ss_link).expect("SS-2022 URI must parse");
        assert!(!prof.password.contains("%3A"));
        assert!(prof.password.contains(':'));

        let corrupt_ss = ProxyProfile {
            protocol: "shadowsocks".into(),
            name: "CorruptCipher".into(),
            server: "8.8.4.4".into(),
            server_port: 8388,
            method: "bad\u{0007}cipher".into(),
            cipher: "bad\u{0007}cipher".into(),
            password: "secret".into(),
            ..Default::default()
        };
        let (valid, _) = filter_and_deduplicate_with_stats(&[prof, corrupt_ss], false, true);
        assert_eq!(valid.len(), 2);
        assert_eq!(valid[0].method, "2022-blake3-aes-256-gcm");
        assert_eq!(valid[1].method, "aes-128-gcm");
        assert_eq!(valid[1].cipher, "aes-128-gcm");

        let sb = build_singbox_config(&valid, false, false, true);
        assert!(!sb.contains("bad\u{0007}cipher"));
        let mh = build_mihomo_config(&valid, false, false, true);
        assert!(!mh.contains("bad\u{0007}cipher"));
    }

    #[test]
    fn test_bpf_binary_header_with_non_utf8_prefix_before_json() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let payload = b"\x08singbox\x00\x00\xf6\x92]{\n  \"outbounds\": [{\"type\":\"vless\",\"tag\":\"BpfNode\",\"server\":\"8.8.8.8\",\"server_port\":443,\"uuid\":\"550e8400-e29b-41d4-a716-446655440000\"}]\n}\n";
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(payload).unwrap();
        let mut raw = vec![0x03u8, 0x01u8];
        raw.extend_from_slice(&gz.finish().unwrap());

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let dec = rt
            .block_on(crate::pipeline::decode_bytes_sync_or_async(
                &raw,
                "sample.bpf",
                &[],
                &[],
                &ProxyMode::DirectOnly,
                "",
                0,
            ))
            .expect("BPF with binary prefix before JSON must decode");
        assert_eq!(dec.profiles.len(), 1);
        assert_eq!(dec.profiles[0].server, "8.8.8.8");

        let legacy_ssh = "[SSH Server 1: Test]\nHost: 188.213.26.23\nPort: 22\nUsername: demo\nPassword: pass\n";
        let dec_ssh = rt
            .block_on(crate::pipeline::decode_bytes_sync_or_async(
                legacy_ssh.as_bytes(),
                "Decrypted_All_SSH.txt",
                &[],
                &[],
                &ProxyMode::DirectOnly,
                "",
                0,
            ))
            .expect("Legacy SSH text dump must decode");
        assert_eq!(dec_ssh.profiles.len(), 1);
        assert_eq!(dec_ssh.profiles[0].protocol, "ssh");

        let ovpn_raw = "client\ndev tun\nproto tcp\nremote ovpn1.example.com 443\nremote ovpn2.example.com 1194\n<ca>\nCERT\n</ca>\n";
        let dec_ovpn = rt
            .block_on(crate::pipeline::decode_bytes_sync_or_async(
                ovpn_raw.as_bytes(),
                "test.ovpn",
                &[],
                &[],
                &ProxyMode::DirectOnly,
                "",
                0,
            ))
            .expect("Multi-remote OpenVPN must decode");
        assert_eq!(dec_ovpn.profiles.len(), 2);
        let (valid_ovpn, _) = filter_and_deduplicate_with_stats(&dec_ovpn.profiles, false, true);
        assert_eq!(valid_ovpn.len(), 2);
    }

    #[test]
    fn test_media_magic_and_cancellation_protections() {
        use crate::models::{ProcessOptions, SourceFileEntry, SourceKind};
        use crate::pipeline::{detect_non_config_media_magic, process_batch_cancellable};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        // 1. MP4 fake .npvt instant rejection without UTF-8/regex hang
        let mut fake_mp4 = vec![0x00, 0x00, 0x00, 0x20, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'];
        fake_mp4.resize(1024 * 128, 0xAA);
        assert!(detect_non_config_media_magic(&fake_mp4).is_some());

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let err = rt
            .block_on(crate::pipeline::decode_bytes_sync_or_async(
                &fake_mp4,
                "FakeVideo.npvt",
                &[],
                &[],
                &ProxyMode::DirectOnly,
                "",
                0,
            ))
            .unwrap_err();
        assert!(!err.needs_password);
        assert!(err.message.contains("MP4"));

        // 2. Cooperative cancellation aborts immediately before processing queue
        let cancel_flag = Arc::new(AtomicBool::new(true));
        let dummy_src = vec![SourceFileEntry {
            id: "1".into(),
            name: "node.txt".into(),
            path: None,
            size: 10,
            kind: SourceKind::File,
            raw_content: Some("vless://550e8400-e29b-41d4-a716-446655440000@1.1.1.1:443#N1".into()),
        }];
        let res = rt.block_on(process_batch_cancellable(
            &dummy_src,
            "",
            "",
            &[],
            &[],
            &ProcessOptions::default(),
            None,
            Some(cancel_flag),
        ));
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("متوقف"));
    }

    #[test]
    fn test_duplicate_node_names_fast_counter_uniqueness() {
        let mut profiles = Vec::with_capacity(1200);
        for i in 0..1200 {
            profiles.push(ProxyProfile {
                protocol: "vless".into(),
                name: "SameName".into(),
                server: format!("192.0.2.{}", (i % 250) + 1),
                server_port: 1000 + (i as u16),
                uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
                ..Default::default()
            });
        }
        let mh = build_mihomo_config(&profiles, false, false, true);
        assert!(mh.contains("\"SameName #1199\""));
        let sb = build_singbox_config(&profiles, false, false, true);
        assert!(sb.contains("\"SameName #1199\""));
    }
}
