/**
 * AegisCore REST API Client
 * Connects to the C backend running on localhost:9009
 * Auto-refreshes data every 5 seconds by default.
 */

const API_BASE = 'http://127.0.0.1:9009/api/v1';

export const API_URL = API_BASE;

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json() as T;
}

/* ── Types ── */
export interface PlatformStatus {
  platform: string;
  version: string;
  api_version: string;
  uptime_seconds: number;
  total_bus_events: number;
  waf_profile: string;
  engines: Record<string, string>;
  api_requests: number;
}

export interface AllStats {
  event_bus: { total_events: number; capacity: number };
  av: {
    enabled: boolean;
    total_scans: number;
    files_scanned: number;
    processes_scanned: number;
    threats_found: number;
    threats_quarantined: number;
    false_positive_rate: number;
    last_full_scan_ts: number;
    next_full_scan_ts: number;
    scan_duration_ms: number;
    hash_db_size: number;
    pattern_count: number;
    processes_watched: number;
    auto_kill: boolean;
    realtime_enabled: boolean;
    memory_scan_enabled: boolean;
    scan_running: boolean;
  };
  webguard: {
    enabled: boolean;
    profile: string;
    rule_count: number;
    requests_inspected: number;
    requests_blocked: number;
    requests_allowed: number;
    attacks_detected: number;
    sqli_count: number;
    xss_count: number;
    rce_count: number;
    lfi_count: number;
    ssrf_count: number;
    log4shell_count: number;
    scanner_detections: number;
    ips_banned: number;
    false_positives_reported: number;
    syswatch_events: number;
    pentest_captures: number;
    block_threshold: number;
    ban_threshold: number;
    rate_limit_rps: number;
    allowlist_count: number;
    blocklist_count: number;
    syswatch_count: number;
  };
  sandbox: {
    enabled: boolean;
    sandbox_count: number;
    proxy_port: number;
    proxy_running: boolean;
    proxy_log_count: number;
    has_admin: boolean;
    total_bytes_sent: number;
    total_bytes_recv: number;
    total_connections: number;
  };
  nexus: {
    enabled: boolean;
    events_processed: number;
    sessions_created: number;
    active_sessions: number;
    incidents_created: number;
    active_incidents: number;
    ioc_count: number;
    ioc_hits: number;
    coordinated_responses: number;
    dedup_dropped: number;
    escalate_threshold: number;
    critical_threshold: number;
  };
  hostguard: {
    initialized: boolean;
    thread_count: number;
    honeypot_count: number;
    ransomware_lockdown: boolean;
    stat_components_scanned: number;
    stat_cve_checks_done: number;
    stat_cve_found: number;
    stat_remediations_applied: number;
    stat_firewall_rules_added: number;
    stat_api_ratelimit_hits: number;
    stat_thread_restarts: number;
    stat_fire_events_published: number;
    stat_updates_auto_installed: number;
    stat_updates_user_required: number;
    stat_ransomware_detections: number;
    stat_processes_killed: number;
  };
  integration: {
    fim_to_av_scans: number;
    process_to_av_watches: number;
    tls_to_hash_checks: number;
    file_to_av_scans: number;
    login_fail_to_bucket: number;
    malware_to_bans: number;
    sandbox_files_scanned: number;
    nexus_escalations: number;
    realtime_blocks: number;
    memory_threats: number;
    hostguard_rescans: number;
  };
  api: { requests_served: number; bytes_sent: number; alerts_in_ring: number };
}

export interface APIAlert {
  id: number;
  timestamp: string;
  engine: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  score: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  payload: string;
  location: string;
  cwe: string;
  attck: string;
  scenario: string;
  blocked: boolean;
  quarantined: boolean;
  process_killed: boolean;
  ip_banned: boolean;
  remediation: string;
}

export interface NexusIncident {
  incident_id: number;
  session_id: number;
  created: string;
  title: string;
  summary: string;
  attacker_ip: string;
  target_ip: string;
  kill_chain_stage: number;
  threat_score: number;
  threat_level: number;
  threat_family: string;
  techniques: string;
  auto_remediated: boolean;
  remediation: string;
}

export interface NexusSession {
  session_id: number;
  attacker_ip: string;
  target_ip: string;
  first_event: string;
  last_event: string;
  kill_chain_stage: number;
  engine_count: number;
  technique_count: number;
  event_count: number;
  base_score: number;
  correlated_score: number;
  threat_level: number;
  threat_family: string;
  ip_banned: boolean;
  process_killed: boolean;
  file_quarantined: boolean;
  network_blocked: boolean;
  response_sent: boolean;
}

export interface IOCEntry {
  type: string;
  value: string;
  threat_actor: string;
  campaign: string;
  attck_tech: string;
  confidence: number;
  hit_count: number;
}

export interface WatchedProcess {
  pid: number;
  name: string;
  path: string;
  parent_pid: number;
  parent_name: string;
  is_suspicious: boolean;
  reads_lsass: boolean;
  connects_to_c2: boolean;
  injected_into: boolean;
  c2_ip: string;
  current_score: number;
  threat_level: number;
  file_renames: number;
  file_deletes: number;
  net_connects: number;
  proc_spawns: number;
  reg_writes: number;
  mem_allocs: number;
  remote_thread: number;
}

export interface SandboxInstance {
  name: string;
  state: string;
  pid: number;
  exe: string;
  start_time: string;
  firewall_active: boolean;
  low_integrity: boolean;
  bytes_sent: number;
  bytes_recv: number;
  connections: number;
}

export interface HostGuardThread {
  id: number;
  name: string;
  alive: boolean;
  last_heartbeat_age_s: number;
  restart_count: number;
}

export interface SoftwareComponent {
  db_id: number;
  name: string;
  version: string;
  type: string;
  os_info: string;
  first_seen: string;
  last_seen: string;
  needs_cve_check: boolean;
  needs_update_check: boolean;
}

export interface HoneypotFile {
  path: string;
  size: number;
  active: boolean;
  created: string;
  sha256: string;
}

export interface WAFRule {
  rule_id: number;
  name: string;
  description: string;
  attack_type: number;
  attck_technique: string;
  severity: number;
  score_weight: number;
  hit_count: number;
  check_uri: boolean;
  check_query: boolean;
  check_body: boolean;
  check_headers: boolean;
  check_cookies: boolean;
}

/* ── API methods ── */
export const api = {
  /* Platform */
  status:  ()                          => apiFetch<PlatformStatus>('/status'),
  stats:   ()                          => apiFetch<AllStats>('/stats'),
  busStats: ()                         => apiFetch<{ capacity: number; total_events: number; handler_count: number }>('/events/bus'),

  /* Alerts */
  alerts: (limit = 50, severity?: string, engine?: string) => {
    let q = `?limit=${limit}`;
    if (severity) q += `&severity=${severity}`;
    if (engine)   q += `&engine=${engine}`;
    return apiFetch<{ alerts: APIAlert[]; total: number; limit: number; ring_size: number }>(`/alerts${q}`);
  },
  clearAlerts: () => apiFetch<{ status: string }>('/alerts/clear', { method: 'POST' }),

  /* ThreatGuard */
  blocks: ()                          => apiFetch<{ blocks: string[]; count: number }>('/blocks'),
  banIP: (ip: string, duration = 3600) =>
    apiFetch<{ status: string; ip: string }>('/blocks', {
      method: 'POST',
      body: JSON.stringify({ ip, duration }),
    }),
  unbanIP: (ip: string)               => apiFetch<{ status: string }>(`/blocks/${ip}`, { method: 'DELETE' }),

  /* PacketGuard AV */
  avStats:    ()                       => apiFetch<AllStats['av']>('/av/stats'),
  avScan:     (path: string)           => apiFetch<{ rc: number; threat_level: number; threat_name: string; threat_family: string; quarantined: boolean }>('/av/scan', {
    method: 'POST',
    body: JSON.stringify({ path }),
  }),
  avFullScan: ()                       => apiFetch<{ status: string }>('/av/full-scan', { method: 'POST' }),
  avProcesses: ()                      => apiFetch<{ processes: WatchedProcess[]; count: number }>('/av/processes'),

  /* WebGuard WAF */
  wafStats:     ()                     => apiFetch<AllStats['webguard']>('/waf/stats'),
  wafRules:     (limit = 50)           => apiFetch<{ rules: WAFRule[]; total_rules: number }>(`/waf/rules?limit=${limit}`),
  wafSetProfile: (profile: string)     => apiFetch<{ status: string; profile: string }>('/waf/profile', {
    method: 'POST',
    body: JSON.stringify({ profile }),
  }),
  wafAllowlist: ()                     => apiFetch<{ allowlist: string[]; count: number }>('/waf/allowlist'),
  wafAddAllowlist: (ip: string)        => apiFetch<{ status: string }>('/waf/allowlist', {
    method: 'POST',
    body: JSON.stringify({ ip }),
  }),
  wafSyswatch:  ()                     => apiFetch<{ syswatch_paths: { path: string; recursive: boolean; change_count: number }[]; count: number; running: boolean }>('/waf/syswatch'),
  wafCaptures:  (limit = 20)           => apiFetch<{ captures: { id: number; timestamp: string; method: string; uri: string; client_ip: string; score: number; blocked: boolean; finding_count: number }[]; total: number }>(`/waf/captures?limit=${limit}`),

  /* SmartSandbox */
  sandboxList:     ()                  => apiFetch<{ sandboxes: SandboxInstance[]; count: number; proxy_port: number; proxy_running: boolean }>('/sandbox/list'),
  sandboxProxyLogs: (limit = 50)       => apiFetch<{ logs: { timestamp: string; method: string; host: string; port: number; sandbox: string; was_blocked: boolean }[]; count: number }>(`/sandbox/proxy-logs?limit=${limit}`),
  sandboxDiagnostics: ()               => apiFetch<{ file_write: { result: number; msg: string }; registry_write: { result: number; msg: string }; lan_access: { result: number; msg: string }; wan_access: { result: number; msg: string }; integrity_level: string }>('/sandbox/diagnostics'),

  /* Nexus Correlator */
  incidents: (limit = 50)             => apiFetch<{ incidents: NexusIncident[]; total: number; returned: number }>(`/incidents?limit=${limit}`),
  sessions:  (limit = 30)             => apiFetch<{ sessions: NexusSession[]; total: number; returned: number }>(`/sessions?limit=${limit}`),
  ioc:       (limit = 50)             => apiFetch<{ ioc: IOCEntry[]; total: number; returned: number }>(`/ioc?limit=${limit}`),
  addIOC:    (entry: { type: string; value: string; actor?: string; campaign?: string; confidence?: number }) =>
    apiFetch<{ status: string }>('/ioc', { method: 'POST', body: JSON.stringify(entry) }),

  /* HostGuard */
  hostguardStats:      ()             => apiFetch<AllStats['hostguard'] & { initialized: boolean; stop_requested: boolean; ransomware_lockdown: boolean; force_rescan_pending: boolean; db_path: string; model: string }>('/hostguard/stats'),
  hostguardThreads:    ()             => apiFetch<{ threads: HostGuardThread[]; heartbeat_timeout_s: number }>('/hostguard/threads'),
  hostguardComponents: (limit = 50)   => apiFetch<{ components: SoftwareComponent[]; total: number }>(`/hostguard/components?limit=${limit}`),
  hostguardCVEs:       ()             => apiFetch<{ total_cve_found: number; total_checks_done: number; remediations_applied: number; recent_remediations: { db_id: number; component: string; risk_level: string; cve_list: string; status: string; executed_at: string }[] }>('/hostguard/cves'),
  hostguardUpdates:    ()             => apiFetch<{ auto_installed: number; user_required: number; pending: { component: string; type: string; current_version: string; latest_version: string; update_safe: boolean; status: string }[] }>('/hostguard/updates'),
  hostguardHoneypots:  ()             => apiFetch<{ count: number; ransomware_lockdown: boolean; files: HoneypotFile[] }>('/hostguard/honeypots'),
  hostguardRansomware: ()             => apiFetch<{ total_detections: number; processes_killed: number; currently_locked_down: boolean; honeypot_count: number }>('/hostguard/ransomware'),
  hostguardForceScan:  ()             => apiFetch<{ status: string }>('/hostguard/scan', { method: 'POST' }),

  /* Integration */
  integrationStats: ()                => apiFetch<AllStats['integration']>('/integration/stats'),
};
