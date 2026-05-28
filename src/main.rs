use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

const DEFAULT_TIMEOUT_MS: u64 = 450;
const SCHEMA_VERSION: &str = "1.1";

const DEFAULT_PORTS: &[u16] = &[
    22,    // SSH
    23,    // Telnet
    53,    // DNS
    80,    // HTTP
    135,   // MSRPC
    139,   // NetBIOS
    443,   // HTTPS
    445,   // SMB
    631,   // IPP / printers
    111,   // RPC bind / NFS support
    1433,  // Microsoft SQL Server
    1521,  // Oracle Database
    2049,  // NFS
    2181,  // ZooKeeper
    3306,  // MySQL / MariaDB
    5432,  // PostgreSQL
    5601,  // Kibana
    5672,  // AMQP / RabbitMQ
    5984,  // CouchDB
    6379,  // Redis
    8086,  // InfluxDB
    8080,  // HTTP alternate
    8443,  // HTTPS alternate
    9092,  // Kafka
    3389,  // RDP
    5900,  // VNC
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    9200,  // Elasticsearch / OpenSearch
    9100,  // JetDirect printers
    11211, // Memcached
    15672, // RabbitMQ management
    27017, // MongoDB
];

const THOROUGH_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389,
    443, 445, 465, 500, 515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1025, 1080, 1099, 1194,
    1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2181, 2375, 2376, 2379, 2380, 3000, 3128, 3268,
    3269, 3306, 3389, 3478, 5000, 5001, 5060, 5061, 5353, 5357, 5432, 5601, 5672, 5900, 5901, 5902,
    5984, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7002, 8000, 8008, 8009, 8080, 8081, 8086, 8181,
    5555, 62078, 7000, 7100, 8060, 8443, 8530, 8531, 8883, 8888, 9000, 9042, 9092, 9093, 9100,
    9200, 9300, 9443, 9999, 10000, 10250, 11211, 15672, 27017, 50070,
];

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn run_command_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    let trimmed = combined.trim().to_string();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn ports_for_profile(profile: &str) -> Option<Vec<u16>> {
    match profile {
        "light" => Some(DEFAULT_PORTS.to_vec()),
        "thorough" => Some(THOROUGH_PORTS.to_vec()),
        _ => None,
    }
}

fn unix_timestamp_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn local_timestamp() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        run_command_capture(
            "powershell",
            &["-NoProfile", "-Command", "Get-Date -Format o"],
        )
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        run_command("date", &["+%Y-%m-%dT%H:%M:%S%z"])
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn hostname() -> Option<String> {
    env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| run_command("hostname", &[]))
}

fn usage(program: &str) {
    eprintln!(
        "Usage:\n  {0}\n  {0} --progress\n  {0} --profile light --progress\n  {0} --detect-target\n  {0} --target 192.168.1.0/24\n  {0} --target 192.168.1.10\n  {0} --timeout-ms 700\n\nDefault profile is thorough. SafeSniff performs permissioned, low-impact TCP service enumeration only.\nIt does not exploit, brute-force, authenticate, persist, or modify remote systems.",
        program
    );
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;

    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn parse_ipv4_cidr(input: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_part, prefix_part) = input.split_once('/')?;
    let ip = ip_part.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix_part.parse::<u8>().ok()?;

    if prefix > 32 {
        return None;
    }

    Some((ip, prefix))
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ipv4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_be_bytes())
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn network_ip_for(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    u32_to_ipv4(ipv4_to_u32(ip) & prefix_to_mask(prefix))
}

fn cidr_label(ip: Ipv4Addr, prefix: u8) -> String {
    format!("{}/{}", network_ip_for(ip, prefix), prefix)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn dotted_netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = ipv4_to_u32(mask);
    let mut prefix = 0;
    let mut seen_zero = false;

    for i in 0..32 {
        let bit = (bits >> (31 - i)) & 1;
        if bit == 1 {
            if seen_zero {
                return None;
            }
            prefix += 1;
        } else {
            seen_zero = true;
        }
    }

    Some(prefix)
}

#[cfg(target_os = "macos")]
fn hex_netmask_to_prefix(mask: &str) -> Option<u8> {
    let trimmed = mask.trim_start_matches("0x");
    let value = u32::from_str_radix(trimmed, 16).ok()?;
    dotted_netmask_to_prefix(u32_to_ipv4(value))
}

fn hosts_from_cidr(network_ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if prefix == 32 {
        return vec![network_ip];
    }

    let mask = prefix_to_mask(prefix);

    let network = ipv4_to_u32(network_ip) & mask;
    let broadcast = network | !mask;

    let mut hosts = Vec::new();

    let start = if prefix >= 31 { network } else { network + 1 };
    let end = if prefix >= 31 {
        broadcast
    } else {
        broadcast - 1
    };

    for value in start..=end {
        hosts.push(u32_to_ipv4(value));
    }

    hosts
}

fn default_local_24() -> Option<(String, Vec<Ipv4Addr>)> {
    let local_ip = get_local_ipv4()?;
    let network = network_ip_for(local_ip, 24);
    let label = cidr_label(local_ip, 24);
    Some((label, hosts_from_cidr(network, 24)))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn default_route_interface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        if let Some(output) = run_command("netstat", &["-rn", "-f", "inet"]) {
            for line in output.lines() {
                let tokens = line.split_whitespace().collect::<Vec<&str>>();
                if tokens.first() == Some(&"default")
                    && let Some(interface) = tokens.last()
                    && interface.chars().any(|ch| ch.is_ascii_alphabetic())
                {
                    return Some((*interface).to_string());
                }
            }
        }

        let output = run_command("route", &["-n", "get", "default"])?;
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix("interface:") {
                return Some(value.trim().to_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = run_command("ip", &["route", "show", "default"])?;
        let mut tokens = output.split_whitespace();
        while let Some(token) = tokens.next() {
            if token == "dev" {
                return tokens.next().map(|value| value.to_string());
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn parse_macos_ifconfig_ipv4(output: &str) -> Option<(Ipv4Addr, u8)> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("inet ") {
            continue;
        }

        let tokens = trimmed.split_whitespace().collect::<Vec<&str>>();
        let ip = tokens.get(1)?.parse::<Ipv4Addr>().ok()?;
        let netmask = tokens
            .windows(2)
            .find_map(|pair| (pair[0] == "netmask").then_some(pair[1]))?;
        let prefix = hex_netmask_to_prefix(netmask)?;

        if !ip.is_loopback() && !ip.is_unspecified() {
            return Some((ip, prefix));
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn parse_linux_ip_addr_ipv4(output: &str) -> Option<(Ipv4Addr, u8)> {
    for line in output.lines() {
        for token in line.split_whitespace() {
            if let Some((ip_part, prefix_part)) = token.split_once('/') {
                let ip = ip_part.parse::<Ipv4Addr>().ok()?;
                let prefix = prefix_part.parse::<u8>().ok()?;
                if prefix <= 32 && !ip.is_loopback() && !ip.is_unspecified() {
                    return Some((ip, prefix));
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn parse_windows_ipconfig_ipv4(output: &str, expected_ip: Ipv4Addr) -> Option<(Ipv4Addr, u8)> {
    let mut saw_expected_ip = false;

    for line in output.lines() {
        let lower = line.to_ascii_lowercase();

        if lower.contains("ipv4") {
            if let Some((_, value)) = line.split_once(':') {
                let candidate = value.trim().trim_end_matches("(Preferred)").trim();
                saw_expected_ip = candidate.parse::<Ipv4Addr>().ok() == Some(expected_ip);
            }
            continue;
        }

        if saw_expected_ip && lower.contains("subnet mask") {
            let mask = line
                .split_once(':')
                .and_then(|(_, value)| value.trim().parse::<Ipv4Addr>().ok())?;
            let prefix = dotted_netmask_to_prefix(mask)?;
            return Some((expected_ip, prefix));
        }
    }

    None
}

fn detect_local_subnet() -> Option<(String, Vec<Ipv4Addr>, TargetDetectionReport)> {
    #[cfg(target_os = "macos")]
    if let Some(interface) = default_route_interface()
        && let Some(output) = run_command("ifconfig", &[&interface])
        && let Some((ip, prefix)) = parse_macos_ifconfig_ipv4(&output)
    {
        let label = cidr_label(ip, prefix);
        let hosts = hosts_from_cidr(network_ip_for(ip, prefix), prefix);
        return Some((
            label,
            hosts,
            TargetDetectionReport {
                source: "default_route_interface",
                interface: Some(interface),
                local_ip: Some(ip.to_string()),
                prefix: Some(prefix),
                confidence: "high",
                note: "Default target derived from the OS default route interface and its configured IPv4 netmask.",
            },
        ));
    }

    #[cfg(target_os = "linux")]
    if let Some(interface) = default_route_interface() {
        if let Some(output) = run_command("ip", &["-o", "-4", "addr", "show", "dev", &interface]) {
            if let Some((ip, prefix)) = parse_linux_ip_addr_ipv4(&output) {
                let label = cidr_label(ip, prefix);
                let hosts = hosts_from_cidr(network_ip_for(ip, prefix), prefix);
                return Some((
                    label,
                    hosts,
                    TargetDetectionReport {
                        source: "default_route_interface",
                        interface: Some(interface),
                        local_ip: Some(ip.to_string()),
                        prefix: Some(prefix),
                        confidence: "high",
                        note: "Default target derived from the OS default route interface and its configured IPv4 prefix.",
                    },
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    if let Some(output) = run_command_capture("ipconfig", &[]) {
        let local_ip = get_local_ipv4()?;
        if let Some((ip, prefix)) = parse_windows_ipconfig_ipv4(&output, local_ip) {
            let label = cidr_label(ip, prefix);
            let hosts = hosts_from_cidr(network_ip_for(ip, prefix), prefix);
            return Some((
                label,
                hosts,
                TargetDetectionReport {
                    source: "ipconfig_matching_local_ip",
                    interface: None,
                    local_ip: Some(ip.to_string()),
                    prefix: Some(prefix),
                    confidence: "medium",
                    note: "Default target derived from the ipconfig adapter containing the local outbound IPv4 address.",
                },
            ));
        }
    }

    let local_ip = get_local_ipv4()?;
    let (label, hosts) = default_local_24()?;
    Some((
        label,
        hosts,
        TargetDetectionReport {
            source: "local_ip_24_fallback",
            interface: None,
            local_ip: Some(local_ip.to_string()),
            prefix: Some(24),
            confidence: "low",
            note: "Could not read an OS interface netmask; fell back to the local IPv4 address with /24. Use --target to override.",
        },
    ))
}

#[derive(Debug, Clone)]
struct ArpHost {
    ip: Ipv4Addr,
    mac: String,
}

#[derive(Debug, Clone, Serialize)]
struct HttpDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    status_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    auth_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect: Option<String>,
    #[serde(skip_serializing)]
    raw_summary: Option<String>,
}

#[derive(Debug, Clone)]
struct HostScan {
    ip: Ipv4Addr,
    ping_reachable: bool,
    ttl: Option<u8>,
    os_guess: &'static str,
    services: Vec<ServiceFinding>,
}

#[derive(Debug, Clone)]
struct ScanConfig {
    target_label: String,
    hosts: Vec<Ipv4Addr>,
    profile: &'static str,
    ports: Vec<u16>,
    timeout_ms: u64,
    local_ip: Option<Ipv4Addr>,
    target_detection: TargetDetectionReport,
    detect_only: bool,
    progress: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TargetDetectionReport {
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<u8>,
    confidence: &'static str,
    note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceFinding {
    port: u16,
    service: &'static str,
    state: &'static str,
    category: &'static str,
    severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_details: Option<HttpDetails>,
    remediation: &'static str,
    evidence: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
struct OsHint {
    guess: &'static str,
    confidence: &'static str,
    source: &'static str,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct DeviceContext {
    label: String,
    likely_role: &'static str,
    likely_os: &'static str,
    confidence: &'static str,
    exposure_level: &'static str,
    headline: String,
    notable_findings: Vec<String>,
    suggested_followups: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SecurityContext {
    review_priority: &'static str,
    posture: &'static str,
    risk_tags: Vec<&'static str>,
    protective_signals: Vec<&'static str>,
    evidence_gaps: Vec<&'static str>,
    ai_correlation_terms: Vec<String>,
    ai_questions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiscoveryReport {
    likely_active: bool,
    ping_reachable: bool,
    ttl: Option<u8>,
    os_guess: &'static str,
    arp_seen: bool,
    open_tcp_service_count: usize,
}

#[derive(Debug, Serialize)]
struct HostReport {
    ip: String,
    status: &'static str,
    is_local_machine: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_hint: Option<String>,
    discovery: DiscoveryReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_hint: Option<&'static str>,
    os_hints: Vec<OsHint>,
    device_context: DeviceContext,
    security_context: SecurityContext,
    services: Vec<ServiceFinding>,
}

#[derive(Debug, Serialize)]
struct InventoryDevice {
    ip: String,
    label: String,
    likely_role: &'static str,
    likely_os: &'static str,
    confidence: &'static str,
    exposure_level: &'static str,
    open_service_count: usize,
    high_count: usize,
    medium_count: usize,
    open_ports: Vec<u16>,
    service_names: Vec<&'static str>,
    security_review_priority: &'static str,
    risk_tags: Vec<&'static str>,
    ai_correlation_terms: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeviceInventory {
    observed_device_count: usize,
    active_with_open_services: usize,
    active_without_open_services: usize,
    inactive_address_count: usize,
    note: &'static str,
    devices: Vec<InventoryDevice>,
}

#[derive(Debug, Serialize)]
struct ObservedHostReport {
    ip: String,
    is_local_machine: bool,
    mac: String,
    mac_type: &'static str,
    vendor_hint: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_hint: Option<String>,
    ping_reachable: bool,
    ttl: Option<u8>,
    os_guess: &'static str,
    source: &'static str,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct SummaryReport {
    overall: &'static str,
    active_hosts: usize,
    inactive_or_unobserved_hosts: usize,
    hosts_with_open_services: usize,
    observed_hosts: usize,
    open_service_count: usize,
    high_count: usize,
    medium_count: usize,
}

#[derive(Debug, Serialize)]
struct ReportMetadata {
    schema_version: &'static str,
    generated_by: &'static str,
    generated_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_at_local: Option<String>,
    scan_started_at_unix: u64,
    scan_finished_at_unix: u64,
    duration_ms: u128,
    scanner_hostname: Option<String>,
    scan_profile: &'static str,
    timeout_ms: u64,
    tested_host_count: usize,
    tested_port_count: usize,
    total_tcp_connect_attempts_planned: usize,
}

#[derive(Debug, Serialize)]
struct SafetyReport {
    exploit_checks: bool,
    credential_attempts: bool,
    bruteforce: bool,
    persistence: bool,
    packet_capture: bool,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    tool: &'static str,
    mode: &'static str,
    metadata: ReportMetadata,
    profile: &'static str,
    target: String,
    target_detection: TargetDetectionReport,
    tested_hosts: usize,
    tested_ports: Vec<u16>,
    device_inventory: DeviceInventory,
    hosts: Vec<HostReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    not_observed_hosts: Vec<String>,
    observed_hosts: Vec<ObservedHostReport>,
    summary: SummaryReport,
    safety: SafetyReport,
}

#[derive(Debug, Serialize)]
struct TargetPreviewReport {
    tool: &'static str,
    mode: &'static str,
    metadata: ReportMetadata,
    profile: &'static str,
    target: String,
    tested_hosts: usize,
    target_detection: TargetDetectionReport,
    safety: SafetyReport,
}

fn extract_ipv4s_from_text(text: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    for token in text.split(|c: char| {
        c.is_whitespace() || c == '(' || c == ')' || c == '[' || c == ']' || c == ','
    }) {
        if let Ok(ip) = token.parse::<Ipv4Addr>()
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            ips.push(ip);
        }
    }

    ips
}

fn token_looks_like_mac(token: &str) -> bool {
    let cleaned = token
        .trim_matches(|c: char| c == '[' || c == ']' || c == '(' || c == ')' || c == ',')
        .to_ascii_lowercase();

    let separator = if cleaned.contains(':') {
        ':'
    } else if cleaned.contains('-') {
        '-'
    } else {
        return false;
    };

    let parts: Vec<&str> = cleaned.split(separator).collect();

    if parts.len() != 6 {
        return false;
    }

    parts.iter().all(|part| {
        !part.is_empty() && part.len() <= 2 && part.chars().all(|ch| ch.is_ascii_hexdigit())
    })
}

fn normalize_mac(token: &str) -> Option<String> {
    let cleaned = token
        .trim_matches(|c: char| c == '[' || c == ']' || c == '(' || c == ')' || c == ',')
        .to_ascii_lowercase()
        .replace('-', ":");

    if !token_looks_like_mac(&cleaned) {
        return None;
    }

    let parts: Vec<String> = cleaned
        .split(':')
        .map(|part| {
            if part.len() == 1 {
                format!("0{}", part)
            } else {
                part.to_string()
            }
        })
        .collect();

    Some(parts.join(":"))
}

fn extract_first_mac_from_line(line: &str) -> Option<String> {
    for token in line.split_whitespace() {
        if let Some(mac) = normalize_mac(token) {
            return Some(mac);
        }
    }

    None
}

fn arp_line_has_real_mac(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();

    if lower.contains("incomplete")
        || lower.contains("failed")
        || lower.contains("no entry")
        || lower.contains("permanent")
        || lower.contains("ff:ff:ff:ff:ff:ff")
        || lower.contains("ff-ff-ff-ff-ff-ff")
    {
        return false;
    }

    line.split_whitespace().any(token_looks_like_mac)
}

fn extract_valid_arp_hosts(text: &str) -> Vec<ArpHost> {
    let mut hosts = Vec::new();

    for line in text.lines() {
        if !arp_line_has_real_mac(line) {
            continue;
        }

        let mac = match extract_first_mac_from_line(line) {
            Some(mac) => mac,
            None => continue,
        };

        for ip in extract_ipv4s_from_text(line) {
            hosts.push(ArpHost {
                ip,
                mac: mac.clone(),
            });
        }
    }

    hosts
}

fn get_arp_cache_hosts() -> Vec<ArpHost> {
    let mut seen_ips = BTreeSet::new();
    let mut hosts = Vec::new();

    if let Some(output) = run_command("arp", &["-a"]) {
        for host in extract_valid_arp_hosts(&output) {
            if seen_ips.insert(host.ip) {
                hosts.push(host);
            }
        }
    }

    hosts
}

fn ipv4_in_target(ip: Ipv4Addr, target_hosts: &[Ipv4Addr]) -> bool {
    target_hosts.contains(&ip)
}

fn vendor_hint(mac: &str) -> &'static str {
    let prefix = mac.get(0..8).unwrap_or("");

    match prefix {
        // Common Apple OUIs. Modern iPhones often use private randomized MACs, so this is best-effort only.
        "00:03:93" | "00:05:02" | "00:0a:27" | "00:0a:95" | "00:0d:93" | "00:11:24"
        | "00:14:51" | "00:16:cb" | "00:17:f2" | "00:19:e3" | "00:1b:63" | "00:1c:b3"
        | "00:1d:4f" | "00:1e:52" | "00:1e:c2" | "00:1f:5b" | "00:1f:f3" | "00:21:e9"
        | "00:22:41" | "00:23:12" | "00:23:32" | "00:23:6c" | "00:23:df" | "00:24:36"
        | "00:25:00" | "00:25:4b" | "00:25:bc" | "00:26:08" | "00:26:4a" | "00:26:b0"
        | "04:0c:ce" | "04:15:52" | "04:1e:64" | "04:26:65" | "04:48:9a" | "04:52:f3"
        | "04:54:53" | "04:69:f8" | "04:db:56" | "04:e5:36" | "08:00:07" | "08:66:98"
        | "08:70:45" | "0c:30:21" | "0c:3e:9f" | "10:40:f3" | "10:93:e9" | "14:10:9f"
        | "14:5a:05" | "18:34:51" | "18:65:90" | "18:af:61" | "20:ab:37" | "24:a0:74"
        | "28:cf:e9" | "28:e0:2c" | "2c:54:91" | "34:15:9e" | "38:ca:da" | "3c:07:54"
        | "40:30:04" | "44:00:10" | "48:60:bc" | "4c:8d:79" | "5c:95:ae" | "60:03:08"
        | "64:b9:e8" | "68:5b:35" | "70:56:81" | "78:31:c1" | "7c:04:d0" | "80:be:05"
        | "84:38:35" | "88:63:df" | "8c:85:90" | "90:b2:1f" | "98:01:a7" | "a4:5e:60"
        | "a8:66:7f" | "ac:bc:32" | "b8:17:c2" | "c0:9f:42" | "c8:2a:14" | "cc:08:e0"
        | "d0:23:db" | "d8:30:62" | "dc:a9:04" | "e0:ac:cb" | "e8:80:2e" | "f0:18:98"
        | "f4:31:c3" => "Apple",

        "00:1a:11" | "00:1d:60" | "00:24:fe" | "08:96:d7" | "24:65:11" | "34:31:c4"
        | "38:10:d5" | "44:4e:6d" | "4c:09:d4" | "5c:49:79" | "74:42:7f" | "9c:c7:a6"
        | "bc:05:43" | "c8:0e:14" | "cc:ce:1e" => "AVM / FRITZ!Box",

        "00:14:22" | "00:1b:21" | "00:22:19" | "3c:97:0e" | "44:8a:5b" | "58:11:22"
        | "78:2b:cb" | "84:7b:eb" | "a4:bb:6d" | "b8:ca:3a" | "d4:be:d9" | "f8:bc:12" => "Dell",

        "00:1a:4b" | "00:1e:65" | "00:25:b3" | "3c:d9:2b" | "44:37:e6" | "6c:88:14"
        | "70:5a:0f" | "80:19:34" | "a0:88:b4" | "b4:b5:2f" | "c8:cb:b8" | "ec:8e:b5" => {
            "Hewlett Packard"
        }

        "00:16:6f" | "00:19:e0" | "00:21:5c" | "00:23:4d" | "00:26:5e" | "28:18:78"
        | "34:97:f6" | "44:6d:57" | "50:3e:aa" | "60:f2:62" | "98:fa:9b" | "c8:f7:33"
        | "d8:cb:8a" => "Samsung",

        "18:d6:c7" | "20:df:b9" | "30:b5:c2" | "50:c7:bf" | "68:ff:7b" | "74:da:38"
        | "98:de:d0" | "a0:f3:c1" | "b0:be:76" | "c0:25:e9" | "e8:94:f6" | "f4:f5:d8" => "TP-Link",

        "00:1e:58" | "00:22:75" | "00:26:18" | "08:3e:8e" | "20:e8:82" | "28:6c:07"
        | "50:64:2b" | "70:4f:57" | "84:c7:ea" | "ac:84:c6" | "c4:2c:03" | "f8:1a:67" => "D-Link",

        "00:15:5d" => "Microsoft Hyper-V",
        "00:05:69" | "00:0c:29" | "00:1c:14" | "00:50:56" => "VMware",
        "08:00:27" => "VirtualBox",
        "00:1c:42" => "Parallels",

        _ => "unknown",
    }
}

fn mac_type(mac: &str) -> &'static str {
    let first_octet = match mac.get(0..2).and_then(|s| u8::from_str_radix(s, 16).ok()) {
        Some(value) => value,
        None => return "unknown",
    };

    let multicast = (first_octet & 0b0000_0001) != 0;
    let locally_administered = (first_octet & 0b0000_0010) != 0;

    if multicast {
        "multicast_or_invalid_for_host"
    } else if locally_administered {
        "locally_administered_or_randomized"
    } else {
        "globally_administered"
    }
}

fn extract_ttl(text: &str) -> Option<u8> {
    let lower = text.to_ascii_lowercase();
    let pos = lower.find("ttl=")?;
    let after = &lower[pos + 4..];
    let digits: String = after.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    digits.parse::<u8>().ok()
}

fn os_guess_from_ttl(ttl: Option<u8>) -> &'static str {
    match ttl {
        Some(value) if value <= 64 => "unix_like_or_mobile_probable",
        Some(value) if value <= 128 => "windows_probable",
        Some(_) => "network_device_probable",
        None => "unknown",
    }
}

fn ping_host(ip: Ipv4Addr, timeout_ms: u64) -> (bool, Option<u8>, &'static str) {
    #[cfg(target_os = "windows")]
    let output = run_command_capture(
        "ping",
        &["-n", "1", "-w", &timeout_ms.to_string(), &ip.to_string()],
    );

    #[cfg(target_os = "macos")]
    let output = run_command_capture(
        "ping",
        &["-c", "1", "-W", &timeout_ms.to_string(), &ip.to_string()],
    );

    #[cfg(target_os = "linux")]
    let output = run_command_capture(
        "ping",
        &[
            "-c",
            "1",
            "-W",
            &timeout_ms.div_ceil(1000).max(1).to_string(),
            &ip.to_string(),
        ],
    );

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let output: Option<String> = None;

    match output {
        Some(text) => {
            let ttl = extract_ttl(&text);
            let reachable = ttl.is_some()
                || text.to_ascii_lowercase().contains("bytes from")
                || text.to_ascii_lowercase().contains("reply from");
            (reachable, ttl, os_guess_from_ttl(ttl))
        }
        None => (false, None, "unknown"),
    }
}

fn reverse_dns_name(ip: Ipv4Addr) -> Option<String> {
    #[cfg(target_os = "windows")]
    let output = run_command_capture("nslookup", &[&ip.to_string()]);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let output = run_command_capture("nslookup", &[&ip.to_string()])
        .or_else(|| run_command_capture("host", &[&ip.to_string()]));

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let output: Option<String> = None;

    let text = output?;

    for line in text.lines() {
        let lower = line.to_ascii_lowercase();

        if lower.contains("name =") {
            return line
                .split("name =")
                .nth(1)
                .map(|s| s.trim().trim_end_matches('.').to_string());
        }

        if lower.starts_with("name:") {
            return line
                .split(':')
                .nth(1)
                .map(|s| s.trim().trim_end_matches('.').to_string());
        }

        if lower.contains("domain name pointer") {
            return line
                .split("domain name pointer")
                .nth(1)
                .map(|s| s.trim().trim_end_matches('.').to_string());
        }
    }

    None
}

fn netbios_name(ip: Ipv4Addr) -> Option<String> {
    #[cfg(target_os = "windows")]
    let output = run_command_capture("nbtstat", &["-A", &ip.to_string()]);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let output = run_command_capture("nmblookup", &["-A", &ip.to_string()]);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let output: Option<String> = None;

    let text = output?;

    for line in text.lines() {
        if line.contains("<00>") && line.to_ascii_uppercase().contains("UNIQUE") {
            return line.split_whitespace().next().map(|s| s.to_string());
        }
    }

    None
}

fn name_hint(ip: Ipv4Addr) -> Option<String> {
    reverse_dns_name(ip).or_else(|| netbios_name(ip))
}

fn observed_arp_reports(
    arp_hosts: &[ArpHost],
    target_hosts: &[Ipv4Addr],
    timeout_ms: u64,
    local_ip: Option<Ipv4Addr>,
) -> Vec<ObservedHostReport> {
    let mut rows = Vec::new();

    for host in arp_hosts {
        if ipv4_in_target(host.ip, target_hosts) {
            let (ping_reachable, ttl, os_guess) = ping_host(host.ip, timeout_ms);
            let name = name_hint(host.ip);
            let is_local_machine = local_ip.map(|ip| ip == host.ip).unwrap_or(false);

            rows.push(ObservedHostReport {
                ip: host.ip.to_string(),
                is_local_machine,
                mac: host.mac.clone(),
                mac_type: mac_type(&host.mac),
                vendor_hint: vendor_hint(&host.mac),
                name_hint: name,
                ping_reachable,
                ttl,
                os_guess,
                source: "arp_cache",
                note: "Observed in local ARP cache; device may expose no tested TCP services. Vendor and OS guesses are best-effort.",
            });
        }
    }

    rows
}

fn count_arp_hosts_in_target(arp_hosts: &[ArpHost], target_hosts: &[Ipv4Addr]) -> usize {
    arp_hosts
        .iter()
        .filter(|host| ipv4_in_target(host.ip, target_hosts))
        .count()
}

fn arp_host_map(arp_hosts: &[ArpHost], target_hosts: &[Ipv4Addr]) -> BTreeMap<Ipv4Addr, ArpHost> {
    let mut map = BTreeMap::new();

    for host in arp_hosts {
        if ipv4_in_target(host.ip, target_hosts) {
            map.entry(host.ip).or_insert_with(|| host.clone());
        }
    }

    map
}

fn service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        69 => "tftp",
        111 => "rpcbind",
        80 => "http",
        81 => "http-alt",
        88 => "kerberos",
        110 => "pop3",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios",
        143 => "imap",
        161 => "snmp",
        162 => "snmp-trap",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "ike",
        515 => "lpd-printer",
        548 => "afp",
        554 => "rtsp",
        587 => "smtp-submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        902 => "vmware-auth",
        993 => "imaps",
        995 => "pop3s",
        1025 => "windows-rpc-ephemeral",
        1080 => "socks-proxy",
        1099 => "java-rmi",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle-db",
        1723 => "pptp",
        1883 => "mqtt",
        1900 => "ssdp",
        2049 => "nfs",
        2082 => "cpanel",
        2083 => "cpanel-https",
        2181 => "zookeeper",
        2375 => "docker-api",
        2376 => "docker-api-tls",
        2379 => "etcd-client",
        2380 => "etcd-peer",
        3000 => "dev-web",
        3128 => "http-proxy",
        3268 => "ldap-global-catalog",
        3269 => "ldaps-global-catalog",
        3306 => "mysql-mariadb",
        5432 => "postgresql",
        3478 => "stun-turn",
        5000 => "upnp-dev-web",
        5001 => "nas-admin-https",
        5060 => "sip",
        5061 => "sips",
        5353 => "mdns",
        5357 => "wsdapi",
        5555 => "android-debug-bridge",
        5601 => "kibana",
        5672 => "amqp-rabbitmq",
        5901 => "vnc-1",
        5902 => "vnc-2",
        5984 => "couchdb",
        6379 => "redis",
        6000 => "x11",
        6443 => "kubernetes-api",
        6667 => "irc",
        7000 => "airplay",
        7001 => "weblogic",
        7002 => "weblogic-ssl",
        7100 => "airplay-alt",
        8000 => "http-dev",
        8008 => "http-alt",
        8009 => "ajp",
        8060 => "roku-ecp",
        8086 => "influxdb",
        8080 => "http-alt",
        8081 => "http-alt",
        8181 => "http-alt",
        8443 => "https-alt",
        8530 => "wsus",
        8531 => "wsus-ssl",
        8883 => "mqtt-tls",
        8888 => "http-alt",
        9000 => "admin-dev-service",
        9042 => "cassandra",
        9092 => "kafka",
        9093 => "kafka-tls",
        3389 => "rdp",
        5900 => "vnc",
        5985 => "winrm-http",
        5986 => "winrm-https",
        9200 => "elasticsearch-opensearch",
        9300 => "elasticsearch-transport",
        9443 => "https-admin-alt",
        9100 => "jetdirect",
        9999 => "admin-alt",
        10000 => "webmin",
        10250 => "kubelet",
        11211 => "memcached",
        15672 => "rabbitmq-management",
        62078 => "ios-lockdown",
        27017 => "mongodb",
        50070 => "hadoop-name-node",
        _ => "unknown",
    }
}

fn service_category(port: u16) -> &'static str {
    match port {
        1433 | 1521 | 3306 | 5432 | 5984 | 6379 | 8086 | 9042 | 9200 | 9300 | 11211 | 27017 => {
            "database_or_datastore"
        }
        2181 | 2379 | 2380 | 5672 | 8883 | 9092 | 9093 | 15672 => "message_queue_or_coordination",
        20 | 21 | 111 | 135 | 137 | 138 | 139 | 445 | 548 | 873 | 2049 => "file_sharing_or_rpc",
        22 | 23 | 902 | 1194 | 1723 | 2375 | 2376 | 3389 | 5555 | 5900 | 5901 | 5902 | 5985
        | 5986 | 6443 | 10250 => "remote_access_or_management",
        80 | 81 | 443 | 554 | 5601 | 631 | 2082 | 2083 | 3000 | 5000 | 5001 | 5357 | 7000
        | 7001 | 7002 | 7100 | 8000 | 8008 | 8009 | 8060 | 8080 | 8081 | 8181 | 8443 | 8530
        | 8531 | 8888 | 9000 | 9100 | 9443 | 9999 | 10000 | 50070 | 62078 => {
            "web_admin_or_device_service"
        }
        25 | 110 | 143 | 465 | 587 | 993 | 995 => "mail_service",
        88 | 389 | 636 | 3268 | 3269 => "identity_or_directory",
        53 | 69 | 123 | 161 | 162 | 500 | 1883 | 1900 | 3128 | 3478 | 5060 | 5061 | 5353 | 6667 => {
            "network_service"
        }
        _ => "unknown",
    }
}

fn supports_http_probe(port: u16) -> bool {
    matches!(
        port,
        80 | 81
            | 554
            | 5601
            | 5984
            | 8086
            | 8080
            | 8081
            | 8060
            | 8181
            | 8888
            | 9000
            | 9200
            | 9999
            | 10000
            | 15672
            | 50070
    )
}

fn supports_banner_probe(port: u16) -> bool {
    matches!(
        port,
        21 | 22
            | 23
            | 25
            | 110
            | 143
            | 1433
            | 1883
            | 3306
            | 5432
            | 5672
            | 6379
            | 9042
            | 27017
            | 62078
    )
}

fn evidence_for_port(port: u16) -> Vec<&'static str> {
    let mut evidence = vec!["tcp_connect"];

    if supports_http_probe(port) {
        evidence.push("http_head");
    }

    if supports_banner_probe(port) {
        evidence.push("banner_read");
    }

    if matches!(
        port,
        111 | 1433
            | 1521
            | 2049
            | 2181
            | 2375
            | 2376
            | 2379
            | 2380
            | 3306
            | 5432
            | 5601
            | 5672
            | 5984
            | 6379
            | 6443
            | 7000
            | 7100
            | 8060
            | 8086
            | 8883
            | 9042
            | 9092
            | 9093
            | 9200
            | 9300
            | 10250
            | 11211
            | 15672
            | 27017
            | 50070
    ) {
        evidence.push("common_database_or_infra_port");
    }

    evidence
}

fn severity_for_port(port: u16) -> &'static str {
    match port {
        21 | 23 | 5555 | 3389 | 5900 | 5901 | 5902 | 5985 | 5986 | 6000 => "high",
        111 | 135 | 137 | 138 | 139 | 445 | 548 | 873 | 2049 => "high",
        1433 | 1521 | 2181 | 2375 | 2376 | 2379 | 2380 | 3306 | 5432 | 5672 | 5984 | 6379
        | 6443 | 8086 | 8883 | 9042 | 9092 | 9093 | 9200 | 9300 | 10250 | 11211 | 15672 | 27017
        | 50070 => "high",
        22 | 25 | 80 | 81 | 88 | 110 | 143 | 389 | 443 | 465 | 554 | 587 | 631 | 636 | 993
        | 995 | 1080 | 1099 | 1883 | 3000 | 3128 | 3268 | 3269 | 5000 | 5001 | 5601 | 7000
        | 7001 | 7002 | 7100 | 8000 | 8008 | 8009 | 8060 | 8080 | 8081 | 8181 | 8443 | 8888
        | 9000 | 9100 | 9443 | 9999 | 10000 | 62078 => "medium",
        53 => "info",
        _ => "info",
    }
}

fn remediation_hint(port: u16) -> &'static str {
    match port {
        22 => {
            "Confirm SSH is required; restrict by firewall or admin subnet; disable password auth where possible."
        }
        23 => "Disable Telnet; replace with SSH.",
        53 => "Confirm DNS exposure is intended and not an open resolver.",
        80 => "Confirm HTTP admin/service exposure is intended; prefer HTTPS and authentication.",
        135 => "Review Windows RPC exposure; restrict to trusted local hosts where possible.",
        139 => "Review legacy NetBIOS exposure; disable if not required.",
        443 => "Confirm HTTPS service/admin panel exposure is intended and patched.",
        445 => "Review SMB exposure; disable SMBv1; restrict file sharing to trusted hosts.",
        631 => "Review printer/IPP exposure; restrict printer management access.",
        111 => "Review RPC bind exposure; restrict NFS/RPC services to trusted hosts.",
        21 => "Review FTP exposure; prefer SFTP/SSH or restrict to trusted hosts.",
        25 | 110 | 143 | 465 | 587 | 993 | 995 => {
            "Review mail service exposure; confirm it is intentional, patched, and access-controlled."
        }
        389 | 636 | 3268 | 3269 => {
            "Review directory service exposure; restrict LDAP/LDAPS to trusted systems."
        }
        548 | 873 => "Review file sharing exposure; restrict shares to trusted clients.",
        902 => "Review VMware management exposure; restrict to admin hosts.",
        1080 | 3128 => "Review proxy exposure; prevent unauthorized proxy use.",
        1099 => "Review Java RMI exposure; restrict to trusted application hosts.",
        1883 | 8883 => "Review MQTT exposure; require authentication and restrict clients.",
        5555 => {
            "Review Android Debug Bridge exposure; disable ADB over network unless explicitly needed."
        }
        2375 | 2376 => "Review Docker API exposure; never expose unauthenticated Docker API.",
        2379 | 2380 => {
            "Review etcd exposure; restrict to cluster hosts and require authentication."
        }
        1433 => {
            "Review SQL Server exposure; restrict by firewall and require strong authentication."
        }
        1521 => "Review Oracle Database listener exposure; restrict to application/admin hosts.",
        2049 => "Review NFS exposure; restrict exports and client networks.",
        2181 => "Review ZooKeeper exposure; restrict to cluster/admin hosts.",
        3306 => "Review MySQL/MariaDB exposure; restrict by firewall and bind only where needed.",
        5432 => "Review PostgreSQL exposure; restrict by firewall and pg_hba policy.",
        5601 => "Review Kibana exposure; require authentication and restrict management access.",
        5672 => "Review AMQP/RabbitMQ exposure; restrict brokers to trusted clients.",
        5901 | 5902 => {
            "Restrict or disable VNC; avoid unauthenticated/weakly authenticated remote desktop exposure."
        }
        5984 => "Review CouchDB exposure; require authentication and restrict network access.",
        6379 => {
            "Review Redis exposure; bind locally or restrict by firewall; require authentication where supported."
        }
        8086 => "Review InfluxDB exposure; require authentication and restrict clients.",
        8080 => "Review alternate HTTP admin/service exposure.",
        8443 => "Review alternate HTTPS admin/service exposure.",
        8009 => "Review AJP exposure; restrict to local reverse proxies or trusted hosts.",
        7000 | 7100 => "Review AirPlay exposure; confirm media-sharing access is intended.",
        8060 => {
            "Review Roku control API exposure; restrict guest/client network access where possible."
        }
        6443 => "Review Kubernetes API exposure; restrict to trusted admin networks.",
        9042 => "Review Cassandra exposure; restrict to application/cluster hosts.",
        9092 => "Review Kafka exposure; restrict broker listeners to trusted clients.",
        9093 => "Review Kafka TLS exposure; restrict broker listeners to trusted clients.",
        3389 => {
            "Restrict RDP; require NLA; avoid broad LAN exposure unless operationally required."
        }
        5900 => {
            "Restrict or disable VNC; avoid unauthenticated/weakly authenticated remote desktop exposure."
        }
        5985 => "Review WinRM HTTP exposure; prefer HTTPS and restrict management scope.",
        5986 => "Review WinRM HTTPS exposure; restrict management scope.",
        9200 => {
            "Review Elasticsearch/OpenSearch exposure; require authentication and restrict network access."
        }
        9300 => "Review Elasticsearch/OpenSearch transport exposure; restrict to cluster hosts.",
        9100 => "Review raw printer port exposure; restrict to trusted print clients.",
        10250 => "Review kubelet exposure; restrict to cluster/control-plane hosts.",
        11211 => "Review Memcached exposure; bind locally or restrict by firewall.",
        15672 => {
            "Review RabbitMQ management UI exposure; require authentication and restrict admins."
        }
        62078 => {
            "Review iOS lockdown service exposure; this usually indicates an Apple mobile device."
        }
        27017 => "Review MongoDB exposure; require authentication and restrict by firewall.",
        50070 => "Review Hadoop web UI exposure; restrict to trusted admin hosts.",
        _ => "Review whether this exposed service is required.",
    }
}

fn read_initial_banner(stream: &mut TcpStream, timeout_ms: u64) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok()?;

    let mut buffer = [0_u8; 512];
    let n = stream.read(&mut buffer).ok()?;

    if n == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

fn grab_http_details(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<HttpDetails> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok()?;

    let request = format!(
        "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: safesniff/0.1\r\nConnection: close\r\n\r\n",
        ip
    );

    stream.write_all(request.as_bytes()).ok()?;

    let mut buffer = [0_u8; 2048];
    let n = stream.read(&mut buffer).ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buffer[..n]).to_string();

    let mut status_line = None;
    let mut status_code = None;
    let mut server = None;
    let mut auth_required = false;
    let mut redirect = None;
    let mut interesting = Vec::new();

    for line in response.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        if trimmed.starts_with("HTTP/") {
            status_line = Some(trimmed.to_string());
            status_code = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok());
            interesting.push(trimmed.to_string());
        } else if lower.starts_with("server:") {
            server = trimmed
                .split_once(':')
                .map(|(_, value)| value.trim().to_string());
            interesting.push(trimmed.to_string());
        } else if lower.starts_with("www-authenticate:") {
            auth_required = true;
            interesting.push(trimmed.to_string());
        } else if lower.starts_with("location:") {
            redirect = trimmed
                .split_once(':')
                .map(|(_, value)| value.trim().to_string());
            interesting.push(trimmed.to_string());
        }
    }

    Some(HttpDetails {
        status_line,
        status_code,
        server,
        auth_required,
        redirect,
        raw_summary: if interesting.is_empty() {
            None
        } else {
            Some(interesting.join(" | "))
        },
    })
}

fn grab_banner(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<String> {
    if supports_banner_probe(port) {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
        read_initial_banner(&mut stream, timeout_ms)
    } else if supports_http_probe(port) {
        grab_http_details(ip, port, timeout_ms).and_then(|details| details.raw_summary)
    } else {
        None
    }
}

fn probe_port(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<ServiceFinding> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);

    if TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_err() {
        return None;
    }

    let http_details = if supports_http_probe(port) {
        grab_http_details(ip, port, timeout_ms)
    } else {
        None
    };
    let banner = match &http_details {
        Some(details) => details.raw_summary.clone(),
        None => grab_banner(ip, port, timeout_ms),
    };

    Some(ServiceFinding {
        port,
        service: service_name(port),
        state: "open",
        category: service_category(port),
        severity: severity_for_port(port),
        banner,
        http_details,
        remediation: remediation_hint(port),
        evidence: evidence_for_port(port),
    })
}

fn scan_host(ip: Ipv4Addr, timeout_ms: u64, ports: &[u16]) -> HostScan {
    let (ping_reachable, ttl, os_guess) = ping_host(ip, timeout_ms);
    let mut services = Vec::new();

    for port in ports {
        if let Some(service) = probe_port(ip, *port, timeout_ms) {
            services.push(service);
        }
    }

    HostScan {
        ip,
        ping_reachable,
        ttl,
        os_guess,
        services,
    }
}

fn print_progress(
    completed: usize,
    total: usize,
    active_hosts: usize,
    open_services: usize,
    started_at: Instant,
) {
    let width = 30;
    let filled = completed
        .saturating_mul(width)
        .checked_div(total)
        .unwrap_or(width)
        .min(width);
    let empty = width - filled;
    let percent = completed
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(100)
        .min(100);
    let elapsed = started_at.elapsed().as_secs();

    eprint!(
        "\r[{}{}] {:>3}% {}/{} hosts active={} open_services={} elapsed={}s",
        "#".repeat(filled),
        "-".repeat(empty),
        percent,
        completed,
        total,
        active_hosts,
        open_services,
        elapsed
    );
    let _ = std::io::stderr().flush();
}

fn scan_hosts(
    hosts: Vec<Ipv4Addr>,
    timeout_ms: u64,
    progress: bool,
    ports: Vec<u16>,
) -> Vec<HostScan> {
    let mut handles = Vec::new();
    let total = hosts.len();
    let (tx, rx) = mpsc::channel();
    let port_count = ports.len();
    let ports = Arc::new(ports);

    for ip in hosts {
        let tx = tx.clone();
        let ports = Arc::clone(&ports);
        let handle = thread::spawn(move || {
            let scan = scan_host(ip, timeout_ms, &ports);
            let _ = tx.send(scan);
        });
        handles.push(handle);
    }
    drop(tx);

    let mut results = Vec::new();
    let mut active_hosts = 0;
    let mut open_services = 0;
    let started_at = Instant::now();

    if progress {
        eprintln!(
            "Scanning {} hosts x {} ports. Final JSON will print when complete.",
            total, port_count
        );
        print_progress(0, total, 0, 0, started_at);
    }

    for result in rx {
        if result.ping_reachable || !result.services.is_empty() {
            active_hosts += 1;
        }
        open_services += result.services.len();
        results.push(result);

        if progress {
            print_progress(
                results.len(),
                total,
                active_hosts,
                open_services,
                started_at,
            );
        }
    }

    for handle in handles {
        let _ = handle.join();
    }

    if progress {
        eprintln!();
    }

    results
}

fn host_status(scan: &HostScan, arp_seen: bool) -> &'static str {
    if !scan.services.is_empty() {
        "active_with_open_services"
    } else if scan.ping_reachable || arp_seen {
        "active_no_tested_services"
    } else {
        "not_observed"
    }
}

fn push_os_hint(
    hints: &mut Vec<OsHint>,
    guess: &'static str,
    confidence: &'static str,
    source: &'static str,
    evidence: String,
) {
    if !hints
        .iter()
        .any(|hint| hint.guess == guess && hint.source == source)
    {
        hints.push(OsHint {
            guess,
            confidence,
            source,
            evidence,
        });
    }
}

fn os_hints_for_host(
    scan: &HostScan,
    arp_host: Option<&ArpHost>,
    name: Option<&str>,
) -> Vec<OsHint> {
    let mut hints = Vec::new();

    if let Some(ttl) = scan.ttl {
        let guess = os_guess_from_ttl(Some(ttl));
        if guess != "unknown" {
            push_os_hint(
                &mut hints,
                guess,
                "low",
                "icmp_ttl",
                format!("Observed ping TTL {}", ttl),
            );
        }
    }

    if let Some(host) = arp_host {
        let vendor = vendor_hint(&host.mac);
        let mac_kind = mac_type(&host.mac);
        if vendor == "Apple" {
            push_os_hint(
                &mut hints,
                "apple_device_possible",
                "medium",
                "mac_vendor",
                format!("MAC vendor hint is Apple ({})", host.mac),
            );
        }
        if mac_kind == "locally_administered_or_randomized" {
            push_os_hint(
                &mut hints,
                "mobile_or_privacy_randomized_mac_possible",
                "low",
                "mac_type",
                format!("MAC appears locally administered/randomized ({})", host.mac),
            );
        }
    }

    if let Some(name) = name {
        let lower = name.to_ascii_lowercase();
        let hostname_hints = [
            ("iphone", "ios_or_ipados_possible"),
            ("ipad", "ios_or_ipados_possible"),
            ("android", "android_possible"),
            ("pixel", "android_possible"),
            ("galaxy", "android_possible"),
            ("roku", "roku_os_possible"),
            ("chromecast", "android_tv_or_chromecast_possible"),
            ("google-tv", "android_tv_or_chromecast_possible"),
            ("firetv", "fire_tv_android_possible"),
            ("apple-tv", "tvos_possible"),
            ("samsung", "smart_tv_or_samsung_device_possible"),
            ("bravia", "android_tv_or_sony_tv_possible"),
            ("lgwebostv", "lg_webos_tv_possible"),
            ("windows", "windows_possible"),
            ("win-", "windows_possible"),
            ("macbook", "macos_possible"),
            ("imac", "macos_possible"),
        ];

        for (needle, guess) in hostname_hints {
            if lower.contains(needle) {
                push_os_hint(
                    &mut hints,
                    guess,
                    "medium",
                    "name_hint",
                    format!("Name hint contains '{}': {}", needle, name),
                );
            }
        }
    }

    for service in &scan.services {
        match service.port {
            5555 => push_os_hint(
                &mut hints,
                "android_possible",
                "high",
                "open_tcp_port",
                "Android Debug Bridge port 5555 is open".to_string(),
            ),
            62078 => push_os_hint(
                &mut hints,
                "ios_or_ipados_possible",
                "high",
                "open_tcp_port",
                "Apple lockdown service port 62078 is open".to_string(),
            ),
            7000 | 7100 => push_os_hint(
                &mut hints,
                "apple_airplay_device_possible",
                "medium",
                "open_tcp_port",
                format!("AirPlay-related port {} is open", service.port),
            ),
            8008 | 8009 | 8443 => push_os_hint(
                &mut hints,
                "chromecast_android_tv_or_embedded_web_service_possible",
                "low",
                "open_tcp_port",
                format!("Common cast/admin port {} is open", service.port),
            ),
            8060 => push_os_hint(
                &mut hints,
                "roku_os_possible",
                "high",
                "open_tcp_port",
                "Roku ECP port 8060 is open".to_string(),
            ),
            135 | 139 | 445 | 3389 | 5985 | 5986 | 5357 => push_os_hint(
                &mut hints,
                "windows_possible",
                "medium",
                "open_tcp_port",
                format!("Windows-associated port {} is open", service.port),
            ),
            548 => push_os_hint(
                &mut hints,
                "macos_or_apple_file_sharing_possible",
                "medium",
                "open_tcp_port",
                "Apple Filing Protocol port 548 is open".to_string(),
            ),
            9100 | 515 | 631 => push_os_hint(
                &mut hints,
                "printer_or_multifunction_device_possible",
                "medium",
                "open_tcp_port",
                format!("Printer-associated port {} is open", service.port),
            ),
            _ => {}
        }
    }

    hints
}

fn best_os_hint(os_hints: &[OsHint]) -> (&'static str, &'static str) {
    os_hints
        .iter()
        .max_by_key(|hint| {
            let confidence_score = match hint.confidence {
                "high" => 30,
                "medium" => 20,
                "low" => 10,
                _ => 0,
            };
            let specificity_score = match hint.guess {
                "ios_or_ipados_possible"
                | "android_possible"
                | "windows_possible"
                | "macos_possible"
                | "smart_tv_or_samsung_device_possible"
                | "roku_os_possible"
                | "lg_webos_tv_possible"
                | "android_tv_or_sony_tv_possible"
                | "tvos_possible" => 3,
                "apple_airplay_device_possible"
                | "chromecast_android_tv_or_embedded_web_service_possible"
                | "mobile_or_privacy_randomized_mac_possible" => 2,
                _ => 1,
            };
            confidence_score + specificity_score
        })
        .map(|hint| (hint.guess, hint.confidence))
        .unwrap_or(("unknown", "none"))
}

fn has_service(scan: &HostScan, port: u16) -> bool {
    scan.services.iter().any(|service| service.port == port)
}

fn has_service_category(scan: &HostScan, category: &str) -> bool {
    scan.services
        .iter()
        .any(|service| service.category == category)
}

fn likely_role(scan: &HostScan, name: Option<&str>, is_local_machine: bool) -> &'static str {
    let lower_name = name.unwrap_or("").to_ascii_lowercase();
    let short_name = lower_name
        .strip_suffix(".fritz.box")
        .unwrap_or(&lower_name)
        .trim_end_matches('.');

    if is_local_machine {
        return "scanner_workstation";
    }
    if lower_name.contains("samsung")
        || lower_name.contains("tv")
        || has_service(scan, 7000)
        || has_service(scan, 7100)
        || has_service(scan, 8060)
    {
        return "smart_tv_or_media_device";
    }
    if has_service(scan, 62078) || lower_name.contains("iphone") || lower_name.contains("ipad") {
        return "mobile_device";
    }
    if short_name == "fritz"
        || short_name == "router"
        || short_name == "gateway"
        || (has_service(scan, 53) && has_service(scan, 80))
    {
        return "router_or_gateway";
    }
    if has_service(scan, 135) || has_service(scan, 139) || has_service(scan, 445) {
        return "windows_workstation_or_file_sharing_host";
    }
    if has_service(scan, 9100) || has_service(scan, 515) || has_service(scan, 631) {
        return "printer_or_multifunction_device";
    }
    if has_service_category(scan, "database_or_datastore")
        || has_service_category(scan, "message_queue_or_coordination")
    {
        return "server_or_developer_service_host";
    }
    if has_service_category(scan, "remote_access_or_management") {
        return "managed_endpoint";
    }
    if scan.ping_reachable || !scan.services.is_empty() {
        return "active_endpoint";
    }

    "observed_endpoint"
}

fn exposure_level(high_count: usize, medium_count: usize, service_count: usize) -> &'static str {
    if high_count > 0 {
        "high"
    } else if medium_count > 0 {
        "medium"
    } else if service_count > 0 {
        "low"
    } else {
        "minimal"
    }
}

fn service_names_for_category(scan: &HostScan, category: &str) -> Vec<String> {
    scan.services
        .iter()
        .filter(|service| service.category == category)
        .map(|service| format!("{}:{}", service.service, service.port))
        .collect()
}

fn device_context(
    scan: &HostScan,
    name: Option<&str>,
    is_local_machine: bool,
    os_hints: &[OsHint],
) -> DeviceContext {
    let (likely_os, confidence) = best_os_hint(os_hints);
    let high_count = scan
        .services
        .iter()
        .filter(|service| service.severity == "high")
        .count();
    let medium_count = scan
        .services
        .iter()
        .filter(|service| service.severity == "medium")
        .count();
    let service_count = scan.services.len();
    let exposure = exposure_level(high_count, medium_count, service_count);
    let role = likely_role(scan, name, is_local_machine);
    let label = name
        .map(|value| value.to_string())
        .unwrap_or_else(|| scan.ip.to_string());

    let mut notable_findings = Vec::new();
    if is_local_machine {
        notable_findings.push("This is the machine that ran the scan.".to_string());
    }
    if service_count == 0 {
        notable_findings.push(
            "No tested TCP services were open; device was observed by ping or ARP only."
                .to_string(),
        );
    } else {
        notable_findings.push(format!(
            "{} tested TCP service(s) were open: {} high, {} medium.",
            service_count, high_count, medium_count
        ));
    }

    for category in [
        "remote_access_or_management",
        "database_or_datastore",
        "file_sharing_or_rpc",
        "web_admin_or_device_service",
        "identity_or_directory",
        "message_queue_or_coordination",
    ] {
        let names = service_names_for_category(scan, category);
        if !names.is_empty() {
            notable_findings.push(format!("{}: {}", category, names.join(", ")));
        }
    }

    if !os_hints.is_empty() {
        notable_findings.push(format!(
            "Best OS/device hint: {} ({})",
            likely_os, confidence
        ));
    }

    let mut suggested_followups = Vec::new();
    match exposure {
        "high" => suggested_followups
            .push("Review whether high-risk services are expected and restrict them to trusted devices or admin networks.".to_string()),
        "medium" => suggested_followups
            .push("Confirm exposed admin, sharing, or media services are expected on this network.".to_string()),
        "low" => suggested_followups
            .push("Keep the device patched and confirm the exposed service is intentional.".to_string()),
        _ => suggested_followups.push(
            "Identify the device owner/role if it is unfamiliar; no tested services were exposed."
                .to_string(),
        ),
    }

    if likely_os.contains("ios") || likely_os.contains("android") {
        suggested_followups.push(
            "For mobile devices, check OS update status and avoid joining untrusted Wi-Fi networks."
                .to_string(),
        );
    }
    if role == "smart_tv_or_media_device" {
        suggested_followups.push(
            "For smart TVs/media devices, check firmware updates and consider isolating them on a guest/IoT network."
                .to_string(),
        );
    }
    if role == "router_or_gateway" {
        suggested_followups.push(
            "For the router, confirm firmware is current, admin password is strong, and remote administration is disabled."
                .to_string(),
        );
    }

    DeviceContext {
        label: label.clone(),
        likely_role: role,
        likely_os,
        confidence,
        exposure_level: exposure,
        headline: format!(
            "{} appears to be a {} with {} exposure.",
            label, role, exposure
        ),
        notable_findings,
        suggested_followups,
    }
}

fn security_tag_for_service(service: &ServiceFinding) -> Option<&'static str> {
    match service.port {
        21 | 23 | 69 => Some("legacy_cleartext_protocol"),
        22 | 3389 | 5900 | 5901 | 5902 | 5985 | 5986 => Some("remote_admin_surface"),
        135 | 137 | 138 | 139 | 445 | 548 | 873 | 111 | 2049 => Some("file_sharing_or_rpc_surface"),
        1433 | 1521 | 3306 | 5432 | 5984 | 6379 | 8086 | 9042 | 9200 | 9300 | 11211 | 27017 => {
            Some("database_or_datastore_surface")
        }
        2181 | 2379 | 2380 | 5672 | 8883 | 9092 | 9093 | 15672 => {
            Some("infrastructure_or_queue_surface")
        }
        2375 | 2376 => Some("container_management_surface"),
        6443 | 10250 => Some("kubernetes_surface"),
        389 | 636 | 3268 | 3269 | 88 => Some("identity_or_directory_surface"),
        80 | 81 | 443 | 5601 | 7001 | 7002 | 8080 | 8081 | 8181 | 8443 | 8888 | 9000 | 9443
        | 9999 | 10000 | 50070 => Some("web_admin_or_app_surface"),
        5555 => Some("android_debug_bridge_surface"),
        62078 => Some("apple_mobile_pairing_surface"),
        7000 | 7100 | 8060 => Some("media_control_surface"),
        9100 | 515 | 631 => Some("printer_management_surface"),
        53 | 161 | 162 | 1883 | 1900 | 5353 | 5357 | 5060 | 5061 => {
            Some("network_or_discovery_surface")
        }
        _ => None,
    }
}

fn push_unique_static(values: &mut Vec<&'static str>, value: &'static str) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn security_context(
    scan: &HostScan,
    arp_host: Option<&ArpHost>,
    name: Option<&str>,
    is_local_machine: bool,
    context: &DeviceContext,
) -> SecurityContext {
    let mut risk_tags = Vec::new();
    let mut protective_signals = Vec::new();
    let mut evidence_gaps = Vec::new();
    let mut ai_correlation_terms = Vec::new();
    let mut ai_questions = Vec::new();

    for service in &scan.services {
        if let Some(tag) = security_tag_for_service(service) {
            push_unique_static(&mut risk_tags, tag);
        }

        push_unique_string(
            &mut ai_correlation_terms,
            format!("{} tcp/{}", service.service, service.port),
        );

        if let Some(banner) = &service.banner {
            push_unique_string(
                &mut ai_correlation_terms,
                format!("{} banner {}", service.service, banner),
            );
        }
        if let Some(details) = &service.http_details {
            if let Some(server) = &details.server {
                push_unique_string(&mut ai_correlation_terms, format!("http server {}", server));
            }
            if details.auth_required {
                push_unique_static(&mut protective_signals, "http_auth_challenge_observed");
            }
        }
    }

    if scan.services.is_empty() {
        push_unique_static(&mut protective_signals, "no_tested_tcp_services_open");
        push_unique_static(
            &mut evidence_gaps,
            "device_identity_from_network_metadata_only",
        );
    }
    if arp_host.is_none() {
        push_unique_static(&mut evidence_gaps, "mac_vendor_not_observed");
    } else if let Some(host) = arp_host
        && mac_type(&host.mac) == "locally_administered_or_randomized"
    {
        push_unique_static(&mut evidence_gaps, "mac_vendor_may_be_randomized");
    }
    if scan.ttl.is_none() {
        push_unique_static(&mut evidence_gaps, "icmp_ttl_not_observed");
    }
    if context.likely_os == "unknown" {
        push_unique_static(&mut evidence_gaps, "os_family_unknown");
    }
    if context.confidence == "low" || context.confidence == "none" {
        push_unique_static(&mut evidence_gaps, "low_confidence_device_fingerprint");
    }
    if name.is_none() {
        push_unique_static(&mut evidence_gaps, "hostname_not_observed");
    }
    if is_local_machine {
        push_unique_static(&mut protective_signals, "scanner_local_machine_identified");
    }

    push_unique_string(
        &mut ai_correlation_terms,
        format!("role {}", context.likely_role),
    );
    if context.likely_os != "unknown" {
        push_unique_string(
            &mut ai_correlation_terms,
            format!("device os hint {}", context.likely_os),
        );
    }
    if let Some(device_name) = name {
        push_unique_string(
            &mut ai_correlation_terms,
            format!("hostname {}", device_name),
        );
    }
    if let Some(host) = arp_host {
        let vendor = vendor_hint(&host.mac);
        if vendor != "unknown" {
            push_unique_string(&mut ai_correlation_terms, format!("mac vendor {}", vendor));
        }
    }

    if !risk_tags.is_empty() {
        ai_questions.push(format!(
            "Are the observed services expected for a {} on this network?",
            context.likely_role
        ));
        ai_questions.push(
            "Do any observed service banners or product hints match known vulnerable versions?"
                .to_string(),
        );
    }
    if context.likely_role == "smart_tv_or_media_device" {
        ai_questions.push(
            "Is this media or IoT device isolated from laptops, finance systems, and admin devices?"
                .to_string(),
        );
    }
    if context.likely_role == "router_or_gateway" {
        ai_questions.push(
            "Does the gateway firmware, exposed admin surface, and remote administration policy match hardening guidance?"
                .to_string(),
        );
    }
    if context.likely_role == "windows_workstation_or_file_sharing_host" {
        ai_questions.push(
            "Is SMB exposure required, patched, and limited to trusted local clients?".to_string(),
        );
    }
    if context.likely_role == "server_or_developer_service_host" {
        ai_questions.push(
            "Are database, cache, queue, or developer services bound only to trusted interfaces?"
                .to_string(),
        );
    }
    if context.confidence == "low" || context.confidence == "none" {
        ai_questions.push(
            "What extra passive discovery data would improve this device identification?"
                .to_string(),
        );
    }

    let review_priority = match context.exposure_level {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ if context.likely_role == "router_or_gateway" => "medium",
        _ if context.likely_role == "smart_tv_or_media_device" => "low",
        _ => "informational",
    };

    let posture = match context.exposure_level {
        "high" => "review_exposed_high_risk_services",
        "medium" => "review_exposed_services",
        "low" => "low_exposure_service_observed",
        _ => "no_tested_tcp_exposure_observed",
    };

    SecurityContext {
        review_priority,
        posture,
        risk_tags,
        protective_signals,
        evidence_gaps,
        ai_correlation_terms,
        ai_questions,
    }
}

fn host_report(
    scan: &HostScan,
    arp_host: Option<&ArpHost>,
    local_ip: Option<Ipv4Addr>,
) -> HostReport {
    let arp_seen = arp_host.is_some();
    let likely_active = scan.ping_reachable || arp_seen || !scan.services.is_empty();
    let is_local_machine = local_ip.map(|ip| ip == scan.ip).unwrap_or(false);
    let name = if likely_active {
        name_hint(scan.ip)
    } else {
        None
    };

    let os_hints = os_hints_for_host(scan, arp_host, name.as_deref());
    let context = device_context(scan, name.as_deref(), is_local_machine, &os_hints);
    let security = security_context(scan, arp_host, name.as_deref(), is_local_machine, &context);

    let (mac, mac_type_value, vendor) = match arp_host {
        Some(host) => (
            Some(host.mac.clone()),
            Some(mac_type(&host.mac)),
            Some(vendor_hint(&host.mac)),
        ),
        None => (None, None, None),
    };

    HostReport {
        ip: scan.ip.to_string(),
        status: host_status(scan, arp_seen),
        is_local_machine,
        name_hint: name,
        discovery: DiscoveryReport {
            likely_active,
            ping_reachable: scan.ping_reachable,
            ttl: scan.ttl,
            os_guess: scan.os_guess,
            arp_seen,
            open_tcp_service_count: scan.services.len(),
        },
        mac,
        mac_type: mac_type_value,
        vendor_hint: vendor,
        os_hints,
        device_context: context,
        security_context: security,
        services: scan.services.clone(),
    }
}

fn host_reports(
    scans: &[HostScan],
    arp_hosts: &[ArpHost],
    target_hosts: &[Ipv4Addr],
    local_ip: Option<Ipv4Addr>,
) -> Vec<HostReport> {
    let arp_hosts_by_ip = arp_host_map(arp_hosts, target_hosts);
    scans
        .iter()
        .filter(|scan| {
            scan.ping_reachable
                || !scan.services.is_empty()
                || arp_hosts_by_ip.contains_key(&scan.ip)
        })
        .map(|scan| host_report(scan, arp_hosts_by_ip.get(&scan.ip), local_ip))
        .collect()
}

fn not_observed_hosts(
    scans: &[HostScan],
    arp_hosts: &[ArpHost],
    target_hosts: &[Ipv4Addr],
) -> Vec<String> {
    let arp_hosts_by_ip = arp_host_map(arp_hosts, target_hosts);
    scans
        .iter()
        .filter(|scan| {
            !scan.ping_reachable
                && scan.services.is_empty()
                && !arp_hosts_by_ip.contains_key(&scan.ip)
        })
        .map(|scan| scan.ip.to_string())
        .collect()
}

fn inventory_device(host: &HostReport) -> InventoryDevice {
    let high_count = host
        .services
        .iter()
        .filter(|service| service.severity == "high")
        .count();
    let medium_count = host
        .services
        .iter()
        .filter(|service| service.severity == "medium")
        .count();

    InventoryDevice {
        ip: host.ip.clone(),
        label: host.device_context.label.clone(),
        likely_role: host.device_context.likely_role,
        likely_os: host.device_context.likely_os,
        confidence: host.device_context.confidence,
        exposure_level: host.device_context.exposure_level,
        open_service_count: host.services.len(),
        high_count,
        medium_count,
        open_ports: host.services.iter().map(|service| service.port).collect(),
        service_names: host
            .services
            .iter()
            .map(|service| service.service)
            .collect(),
        security_review_priority: host.security_context.review_priority,
        risk_tags: host.security_context.risk_tags.clone(),
        ai_correlation_terms: host.security_context.ai_correlation_terms.clone(),
    }
}

fn device_inventory(hosts: &[HostReport], inactive_address_count: usize) -> DeviceInventory {
    let active_with_open_services = hosts
        .iter()
        .filter(|host| !host.services.is_empty())
        .count();
    let active_without_open_services = hosts.len().saturating_sub(active_with_open_services);

    DeviceInventory {
        observed_device_count: hosts.len(),
        active_with_open_services,
        active_without_open_services,
        inactive_address_count,
        note: "This is the primary device inventory. Hosts listed here were observed by ARP, ping, or open TCP service. Inactive addresses are counted separately and listed later.",
        devices: hosts.iter().map(inventory_device).collect(),
    }
}

fn parse_args() -> Result<ScanConfig, String> {
    let args: Vec<String> = env::args().collect();
    let mut target: Option<String> = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut detect_only = false;
    let mut progress = false;
    let mut profile = "thorough";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                usage(&args[0]);
                std::process::exit(0);
            }
            "--detect-target" | "--show-target" => {
                detect_only = true;
            }
            "--progress" => {
                progress = true;
            }
            "--light" => {
                profile = "light";
            }
            "--profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("--profile requires light or thorough".to_string());
                }
                match args[i].as_str() {
                    "light" => profile = "light",
                    "thorough" => profile = "thorough",
                    _ => return Err("--profile must be light or thorough".to_string()),
                }
            }
            "--target" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "--target requires an IPv4 address or CIDR, e.g. 192.168.1.0/24"
                            .to_string(),
                    );
                }
                target = Some(args[i].clone());
            }
            "--timeout-ms" => {
                i += 1;
                if i >= args.len() {
                    return Err("--timeout-ms requires a number".to_string());
                }
                timeout_ms = args[i]
                    .parse::<u64>()
                    .map_err(|_| "--timeout-ms must be a number".to_string())?;
            }
            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
        i += 1;
    }

    if let Some(target_value) = target {
        if let Some((network, prefix)) = parse_ipv4_cidr(&target_value) {
            if prefix < 24 {
                return Err(
                    "Refusing to scan networks larger than /24 in the safe default build"
                        .to_string(),
                );
            }
            return Ok(ScanConfig {
                target_label: target_value.clone(),
                hosts: hosts_from_cidr(network, prefix),
                profile,
                ports: ports_for_profile(profile).expect("known scan profile should have ports"),
                timeout_ms,
                local_ip: get_local_ipv4(),
                detect_only,
                progress,
                target_detection: TargetDetectionReport {
                    source: "explicit_target",
                    interface: None,
                    local_ip: get_local_ipv4().map(|ip| ip.to_string()),
                    prefix: Some(prefix),
                    confidence: "user_supplied",
                    note: "Target was supplied explicitly with --target.",
                },
            });
        }

        if let Ok(ip) = target_value.parse::<Ipv4Addr>() {
            return Ok(ScanConfig {
                target_label: format!("{}/32", ip),
                hosts: vec![ip],
                profile,
                ports: ports_for_profile(profile).expect("known scan profile should have ports"),
                timeout_ms,
                local_ip: get_local_ipv4(),
                detect_only,
                progress,
                target_detection: TargetDetectionReport {
                    source: "explicit_target",
                    interface: None,
                    local_ip: get_local_ipv4().map(|local_ip| local_ip.to_string()),
                    prefix: Some(32),
                    confidence: "user_supplied",
                    note: "Single host target was supplied explicitly with --target.",
                },
            });
        }

        return Err(
            "Target must be an IPv4 address or CIDR, e.g. 192.168.1.10 or 192.168.1.0/24"
                .to_string(),
        );
    }

    let (label, hosts, target_detection) =
        detect_local_subnet().ok_or_else(|| "Could not determine local IPv4 subnet".to_string())?;

    if target_detection.prefix.is_some_and(|prefix| prefix < 24) {
        return Err(format!(
            "Detected local subnet {} is larger than /24. Refusing to scan it by default; rerun with an explicit --target if this is the intended authorized scope.",
            label
        ));
    }

    Ok(ScanConfig {
        target_label: label,
        hosts,
        profile,
        ports: ports_for_profile(profile).expect("known scan profile should have ports"),
        timeout_ms,
        local_ip: get_local_ipv4(),
        target_detection,
        detect_only,
        progress,
    })
}

fn main() {
    let program_started_at = SystemTime::now();
    let monotonic_started_at = Instant::now();
    let config = match parse_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            usage(
                &env::args()
                    .next()
                    .unwrap_or_else(|| "safesniff".to_string()),
            );
            std::process::exit(1);
        }
    };

    let target_label = config.target_label;
    let target_detection = config.target_detection;
    let timeout_ms = config.timeout_ms;
    let local_ip = config.local_ip;
    let host_count = config.hosts.len();
    let profile = config.profile;
    let ports = config.ports;
    let port_count = ports.len();

    if config.detect_only {
        let finished_at = SystemTime::now();
        let report = TargetPreviewReport {
            tool: "safesniff",
            mode: "target_detection_only",
            metadata: ReportMetadata {
                schema_version: SCHEMA_VERSION,
                generated_by: "safesniff",
                generated_at_unix: unix_timestamp_secs(finished_at),
                generated_at_local: local_timestamp(),
                scan_started_at_unix: unix_timestamp_secs(program_started_at),
                scan_finished_at_unix: unix_timestamp_secs(finished_at),
                duration_ms: monotonic_started_at.elapsed().as_millis(),
                scanner_hostname: hostname(),
                scan_profile: profile,
                timeout_ms,
                tested_host_count: host_count,
                tested_port_count: port_count,
                total_tcp_connect_attempts_planned: 0,
            },
            profile,
            target: target_label,
            tested_hosts: host_count,
            target_detection,
            safety: SafetyReport {
                exploit_checks: false,
                credential_attempts: false,
                bruteforce: false,
                persistence: false,
                packet_capture: false,
            },
        };

        println!(
            "{}",
            serde_json::to_string(&report).expect("target preview should serialize to JSON")
        );
        return;
    }

    let target_hosts = config.hosts.clone();
    let tested_ports = ports.clone();
    let scans = scan_hosts(config.hosts, timeout_ms, config.progress, ports);
    let finished_at = SystemTime::now();
    let observed_arp_hosts = get_arp_cache_hosts();
    let observed_hosts =
        observed_arp_reports(&observed_arp_hosts, &target_hosts, timeout_ms, local_ip);
    let observed_arp_count = count_arp_hosts_in_target(&observed_arp_hosts, &target_hosts);
    let hosts = host_reports(&scans, &observed_arp_hosts, &target_hosts, local_ip);
    let not_observed_hosts = not_observed_hosts(&scans, &observed_arp_hosts, &target_hosts);
    let inventory = device_inventory(&hosts, not_observed_hosts.len());

    let open_service_count = scans.iter().map(|scan| scan.services.len()).sum::<usize>();
    let high_count = scans
        .iter()
        .map(|scan| {
            scan.services
                .iter()
                .filter(|service| service.severity == "high")
                .count()
        })
        .sum::<usize>();
    let medium_count = scans
        .iter()
        .map(|scan| {
            scan.services
                .iter()
                .filter(|service| service.severity == "medium")
                .count()
        })
        .sum::<usize>();
    let hosts_with_open_services = scans
        .iter()
        .filter(|scan| !scan.services.is_empty())
        .count();
    let active_hosts = scans
        .iter()
        .filter(|scan| {
            let arp_seen = observed_arp_hosts
                .iter()
                .any(|host| host.ip == scan.ip && ipv4_in_target(host.ip, &target_hosts));
            scan.ping_reachable || arp_seen || !scan.services.is_empty()
        })
        .count();
    let inactive_or_unobserved_hosts = host_count.saturating_sub(active_hosts);

    let overall = if high_count > 0 {
        "warnings"
    } else if medium_count > 0 {
        "review"
    } else {
        "clear"
    };

    let report = ScanReport {
        tool: "safesniff",
        mode: "permissioned_safe_tcp_enumeration",
        metadata: ReportMetadata {
            schema_version: SCHEMA_VERSION,
            generated_by: "safesniff",
            generated_at_unix: unix_timestamp_secs(finished_at),
            generated_at_local: local_timestamp(),
            scan_started_at_unix: unix_timestamp_secs(program_started_at),
            scan_finished_at_unix: unix_timestamp_secs(finished_at),
            duration_ms: monotonic_started_at.elapsed().as_millis(),
            scanner_hostname: hostname(),
            scan_profile: profile,
            timeout_ms,
            tested_host_count: host_count,
            tested_port_count: tested_ports.len(),
            total_tcp_connect_attempts_planned: host_count.saturating_mul(tested_ports.len()),
        },
        profile,
        target: target_label,
        target_detection,
        tested_hosts: host_count,
        tested_ports,
        device_inventory: inventory,
        hosts,
        not_observed_hosts,
        observed_hosts,
        summary: SummaryReport {
            overall,
            active_hosts,
            inactive_or_unobserved_hosts,
            hosts_with_open_services,
            observed_hosts: observed_arp_count,
            open_service_count,
            high_count,
            medium_count,
        },
        safety: SafetyReport {
            exploit_checks: false,
            credential_attempts: false,
            bruteforce: false,
            persistence: false,
            packet_capture: false,
        },
    };

    println!(
        "{}",
        serde_json::to_string(&report).expect("scan report should serialize to JSON")
    );
}
