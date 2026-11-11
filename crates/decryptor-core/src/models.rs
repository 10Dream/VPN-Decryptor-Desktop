use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact 26 supported protocols matching the original VPN Decryptor Bot.
pub const ALL_SUPPORTED_PROTOCOLS: &[&str] = &[
    "VLESS",
    "VMESS",
    "TROJAN",
    "SHADOWSOCKS",
    "SSR",
    "HYSTERIA2",
    "HYSTERIA",
    "TUIC",
    "WIREGUARD",
    "SSH",
    "OPENVPN",
    "SOCKS5",
    "HTTP",
    "ANYTLS",
    "SHADOWTLS",
    "SNELL",
    "MASQUE",
    "SHADOWQUIC",
    "TRUSTTUNNEL",
    "SUDOKU",
    "MIERU",
    "EASYTIER",
    "TAILSCALE",
    "ZEROTIER",
    "REMATCH",
    "NAIVE",
];

pub const SUPPORTED_FILE_EXTENSIONS: &[&str] = &[
    "npvt", "npvs", "dark", "nm", "hat", "slip", "ssc", "hc", "bpf", "ovpn", "yaml", "yml",
    "json", "txt", "text", "conf", "sub", "list", "zip", "ehi", "inpv",
];

pub const MIHOMO_EXCLUSIVE_PROTOS: &[&str] = &[
    "shadowquic",
    "trusttunnel",
    "sudoku",
    "mieru",
    "easytier",
    "zerotier",
    "rematch",
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AmneziaWgOptions {
    pub jc: Option<i64>,
    pub jmin: Option<i64>,
    pub jmax: Option<i64>,
    pub s1: Option<i64>,
    pub s2: Option<i64>,
    pub s3: Option<i64>,
    pub s4: Option<i64>,
    pub h1: Option<String>,
    pub h2: Option<String>,
    pub h3: Option<String>,
    pub h4: Option<String>,
    pub i1: Option<String>,
    pub wnoise: Option<String>,
    pub wnoisedelay: Option<String>,
    pub wpayloadsize: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpBrutalConfig {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProfile {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub server_port: u16,

    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub psk: String,
    #[serde(default)]
    pub auth_str: String,

    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub encryption: String,
    #[serde(default)]
    pub alter_id: Option<u32>,
    #[serde(default)]
    pub flow: String,

    #[serde(default)]
    pub ssr_protocol: String,
    #[serde(default)]
    pub protocol_param: String,
    #[serde(default)]
    pub obfs: String,
    #[serde(default)]
    pub obfs_password: String,
    #[serde(default)]
    pub obfs_param: String,

    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub reality: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub spider_x: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,

    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default)]
    pub multi_mode: bool,
    #[serde(default)]
    pub header_type: String,
    #[serde(default)]
    pub seed: String,

    // Hy2 / Hy1 / TUIC / AnyTLS / Naive / Tailscale / Mihomo extras
    pub ports: Option<String>,
    pub hop_interval: Option<u64>,
    pub up: Option<String>,
    pub down: Option<String>,
    pub congestion_control: Option<String>,
    pub udp_relay_mode: Option<String>,
    pub idle_session_check_interval: Option<String>,
    pub idle_session_timeout: Option<String>,
    pub min_idle_session: Option<u32>,
    pub client_metadata: Option<String>,
    #[serde(default)]
    pub quic: bool,
    pub insecure_concurrency: Option<u32>,
    pub stream_receive_window: Option<u64>,
    pub udp: Option<bool>,
    pub tcp_brutal: Option<TcpBrutalConfig>,
    pub tailscale_auth_key: Option<String>,
    pub server_public_key: Option<String>,
    pub server_disco_key: Option<String>,
    pub derp_map_url: Option<String>,
    pub derp_region: Option<serde_json::Value>,
    pub network_secret: Option<String>,
    pub version: Option<u32>,

    // WireGuard / MASQUE
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub peer_public_key: String,
    #[serde(default)]
    pub preshared_key: String,
    #[serde(default)]
    pub local_address: String,
    pub ipv6: Option<String>,
    pub mtu: Option<u32>,
    pub reserved: Option<Vec<i32>>,
    pub keepalive: Option<u32>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub remote_dns: Option<String>,
    pub remote_dns_resolve: Option<bool>,
    pub amnezia_options: Option<AmneziaWgOptions>,

    // SSH / OpenVPN
    pub ssh_private_key: Option<String>,
    pub ssh_private_key_passphrase: Option<String>,
    #[serde(default)]
    pub host_key: Vec<String>,
    pub payload: Option<String>,
    pub ovpn_proto: Option<String>,
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub ovpn_config: Option<String>,

    // DNS Tunnel & Raw passthrough
    #[serde(default)]
    pub is_dns_tunnel: bool,
    pub raw_uri: Option<String>,
    pub raw_outbound: Option<serde_json::Value>,

    // Expiry metadata
    pub expiry_raw: Option<String>,
    #[serde(default)]
    pub is_expired: bool,
    pub expire_formatted: Option<String>,

    /// Source configType / nested extra preservation
    #[serde(default)]
    pub config_type: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DnsCompanionEntry {
    pub kind: String,
    pub title: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedSourceOutput {
    pub format_type: String,
    pub source_name: String,
    pub profiles: Vec<ProxyProfile>,
    pub dns_companions: Vec<DnsCompanionEntry>,
    pub expiry_info: Option<ExpiryInfo>,
    pub warning_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryInfo {
    pub has_expiry: bool,
    pub is_expired: bool,
    pub formatted: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptionError {
    pub message: String,
    pub needs_password: bool,
    pub invalid_password: bool,
    pub display_message: Option<String>,
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DecryptionError {}

impl DecryptionError {
    pub fn plain(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            needs_password: false,
            invalid_password: false,
            display_message: None,
        }
    }

    pub fn needs_password(msg: impl Into<String>, display_message: Option<String>) -> Self {
        Self {
            message: msg.into(),
            needs_password: true,
            invalid_password: false,
            display_message,
        }
    }

    pub fn invalid_password(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            needs_password: true,
            invalid_password: true,
            display_message: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputScopeSettings {
    pub mix_all: bool,
    pub per_source: bool,
}

impl Default for OutputScopeSettings {
    fn default() -> Self {
        Self {
            mix_all: true,
            per_source: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputFormatSettings {
    pub xray: bool,
    pub xray_base64: bool,
    pub singbox: bool,
    pub mihomo: bool,
    pub companions: bool,
}

impl Default for OutputFormatSettings {
    fn default() -> Self {
        Self {
            xray: true,
            xray_base64: false,
            singbox: true,
            mihomo: true,
            companions: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolSplitSettings {
    pub all_protocols: bool,
    pub by_protocol: bool,
}

impl Default for ProtocolSplitSettings {
    fn default() -> Self {
        Self {
            all_protocols: true,
            by_protocol: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessOptions {
    #[serde(default = "default_true")]
    pub filter_duplicates: bool,
    #[serde(default = "default_true")]
    pub filter_broken: bool,
    #[serde(default = "default_true")]
    pub ignore_expired: bool,
    #[serde(default)]
    pub limit_max_configs: bool,
    #[serde(default = "default_max_configs")]
    pub max_configs_count: usize,
    #[serde(default = "default_allowed_protocols")]
    pub allowed_protocols: Vec<String>,
    #[serde(default)]
    pub output_scope: OutputScopeSettings,
    #[serde(default)]
    pub output_formats: OutputFormatSettings,
    #[serde(default)]
    pub protocol_split: ProtocolSplitSettings,
    #[serde(default)]
    pub output_dir: String,
    #[serde(default)]
    pub move_decrypted_to_trash: bool,
    #[serde(default)]
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub custom_proxy_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProxyMode {
    #[default]
    AutoDetect,
    SystemOrDirect,
    Custom,
    DirectOnly,
}

fn default_true() -> bool {
    true
}

fn default_max_configs() -> usize {
    500
}

fn default_allowed_protocols() -> Vec<String> {
    ALL_SUPPORTED_PROTOCOLS.iter().map(|s| s.to_string()).collect()
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            filter_duplicates: true,
            filter_broken: true,
            ignore_expired: true,
            limit_max_configs: false,
            max_configs_count: 500,
            allowed_protocols: default_allowed_protocols(),
            output_scope: OutputScopeSettings::default(),
            output_formats: OutputFormatSettings::default(),
            protocol_split: ProtocolSplitSettings::default(),
            output_dir: String::new(),
            move_decrypted_to_trash: false,
            proxy_mode: ProxyMode::AutoDetect,
            custom_proxy_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FilterStats {
    pub total: usize,
    pub valid: usize,
    pub rejected: usize,
    pub duplicates: usize,
    pub expired_count: usize,
    pub proto_counts: BTreeMap<String, usize>,
    pub filter_duplicates: bool,
    pub filter_broken: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceFileEntry {
    pub id: String,
    pub name: String,
    pub path: Option<String>,
    pub size: u64,
    pub kind: SourceKind,
    #[serde(default)]
    pub raw_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    #[default]
    File,
    SubscriptionUrl,
    MessyText,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LockedFileReport {
    pub source_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    pub display_message: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FailedSourceReport {
    pub source_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WrittenFileRecord {
    pub path: String,
    pub rel_path: String,
    pub category: String,
    pub format: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProcessBatchResult {
    pub stats: FilterStats,
    pub total_sources: usize,
    pub succeeded_sources: usize,
    pub moved_to_trash_count: usize,
    pub locked_files: Vec<LockedFileReport>,
    pub failed_sources: Vec<FailedSourceReport>,
    pub written_files: Vec<WrittenFileRecord>,
    pub preview_xray: String,
    pub preview_xray_base64: String,
    pub preview_singbox: String,
    pub preview_mihomo: String,
    pub preview_companions: BTreeMap<String, String>,
    pub output_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEventPayload {
    pub current: usize,
    pub total: usize,
    pub percent: u8,
    pub current_item: String,
    pub stage: String,
}
