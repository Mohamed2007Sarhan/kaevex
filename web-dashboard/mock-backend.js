/**
 * AegisCore v1 — Mock Backend API Server
 * Simulates the fire-engine REST API on port 9009
 * for testing the frontend WITHOUT the compiled C backend.
 *
 * Usage: node mock-backend.js
 * Runs on: http://localhost:9009/api/v1/
 */

const http  = require('http');
const os    = require('os');

const PORT    = 9009;
const BASE    = '/api/v1';
const startTs = Date.now();

// ─── Simulated state ───────────────────────────────────────────────────────
let alertRing = [];
let alertId   = 1;
let incidents = [];
let incId     = 1;
let iocDb     = [];
let bannedIPs = [];
let sessions  = [];

const ENGINES   = ['WebGuard','PacketGuard-AV','SmartSandbox','Nexus','HostGuard','ThreatGuard'];
const SEVERITIES= ['low','medium','high','critical'];
const PROTOCOLS = ['TCP','UDP','HTTP','HTTPS','DNS','TLS','FTP'];
const TYPES     = ['SQLi','XSS','RCE','Scanner','BruteForce','LFI','SSRF','Log4Shell','DirTraversal'];
const KILL_CHAIN= ['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Exfiltration'];
const FAMILIES  = ['APT29','Cobalt Strike','LockBit','Mirai','ZeroDay-Exploit','Generic-RAT'];
const TECHNIQUES= ['T1046','T1059','T1190','T1110','T1078','T1055','T1071','T1203'];

function rnd(a, b)    { return Math.floor(Math.random() * (b - a + 1)) + a; }
function pick(arr)     { return arr[rnd(0, arr.length - 1)]; }
function randomIP()    { return `${rnd(1,254)}.${rnd(0,254)}.${rnd(0,254)}.${rnd(1,254)}`; }
function fmtNow()      { return new Date().toISOString(); }
function uptimeSecs()  { return Math.floor((Date.now() - startTs) / 1000); }

// Generate a fresh alert every 8 seconds
setInterval(() => {
  if (alertRing.length >= 200) alertRing.shift();
  const blocked = Math.random() > 0.35;
  alertRing.push({
    id:             alertId++,
    timestamp:      fmtNow(),
    engine:         pick(ENGINES),
    type:           pick(TYPES),
    severity:       pick(SEVERITIES),
    src_ip:         randomIP(),
    dst_ip:         `192.168.1.${rnd(1,50)}`,
    src_port:       rnd(1024, 65535),
    dst_port:       pick([80, 443, 8080, 22, 3389, 21, 53]),
    proto:          pick(PROTOCOLS),
    payload:        `Detected ${pick(TYPES)} pattern in request body — anomaly score ${rnd(60,99)}`,
    location:       `${pick(['US','RU','CN','BR','DE','IR','TR'])} / DC${rnd(1,5)}`,
    cwe:            `CWE-${pick([79,89,78,22,190,502,611])}`,
    attck:          pick(TECHNIQUES),
    scenario:       `${pick(TYPES)} via HTTP ${pick(['POST','GET','PUT'])} to /api endpoint`,
    blocked:        blocked,
    quarantined:    Math.random() > 0.7,
    process_killed: Math.random() > 0.8,
    ip_banned:      blocked && Math.random() > 0.6,
    remediation:    blocked ? 'Connection terminated and source IP flagged' : 'Monitoring for follow-up attempts',
  });
}, 8000);

// Generate incident every 30 seconds
setInterval(() => {
  if (incidents.length >= 50) incidents.shift();
  const score = rnd(40, 99);
  incidents.push({
    incident_id:       incId++,
    session_id:        `sess-${Date.now()}`,
    created:           fmtNow(),
    title:             `${pick(FAMILIES)} attack chain detected from ${randomIP()}`,
    summary:           `Multi-stage attack correlating ${rnd(3,12)} engine events over ${rnd(2,30)} minutes`,
    attacker_ip:       randomIP(),
    target_ip:         `192.168.1.${rnd(2,20)}`,
    kill_chain_stage:  rnd(1, 7),
    threat_score:      score,
    threat_level:      score >= 80 ? 4 : score >= 60 ? 3 : score >= 40 ? 2 : 1,
    threat_family:     pick(FAMILIES),
    techniques:        `${pick(TECHNIQUES)},${pick(TECHNIQUES)}`,
    auto_remediated:   Math.random() > 0.5,
    remediation:       'Source IP banned + process killed + session terminated',
  });
}, 30000);

// Seed initial data
for (let i = 0; i < 5; i++) {
  const blocked = Math.random() > 0.3;
  alertRing.push({
    id: alertId++, timestamp: fmtNow(), engine: pick(ENGINES),
    type: pick(TYPES), severity: pick(SEVERITIES),
    src_ip: randomIP(), dst_ip: `192.168.1.${rnd(1,50)}`,
    src_port: rnd(1024,65535), dst_port: pick([80,443,8080,22,3389]),
    proto: pick(PROTOCOLS), payload: `Initial seed alert ${i+1}`,
    location: 'US/DC1', cwe: 'CWE-79', attck: pick(TECHNIQUES),
    scenario: 'Attack pattern detected', blocked, quarantined: false,
    process_killed: false, ip_banned: false, remediation: 'Logged',
  });
}
for (let i = 0; i < 3; i++) {
  const score = rnd(55,95);
  incidents.push({
    incident_id: incId++, session_id: `sess-seed-${i}`,
    created: fmtNow(),
    title: `${pick(FAMILIES)} multi-stage attack`,
    summary: `Correlated ${rnd(3,10)} events from ${rnd(2,6)} engines`,
    attacker_ip: randomIP(), target_ip: `192.168.1.${rnd(2,15)}`,
    kill_chain_stage: rnd(2,6), threat_score: score,
    threat_level: score >= 80 ? 4 : 3,
    threat_family: pick(FAMILIES), techniques: `${pick(TECHNIQUES)},${pick(TECHNIQUES)}`,
    auto_remediated: true, remediation: 'Auto-remediated by Nexus engine',
  });
}
iocDb = [
  { type:'IP', value: randomIP(), threat_actor: 'APT29', campaign: 'SolarWinds-2', attck_tech: 'T1078', confidence: 95, hit_count: rnd(0,20) },
  { type:'Domain', value: 'malicious-c2.net', threat_actor: 'LockBit', campaign: 'Ransomware-Q4', attck_tech: 'T1071', confidence: 88, hit_count: rnd(0,5) },
  { type:'Hash', value: 'a1b2c3d4e5f6789012345678901234567890abcd', threat_actor: 'Unknown', campaign: 'Generic-Dropper', attck_tech: 'T1055', confidence: 72, hit_count: 0 },
];

// ─── Stats counters ────────────────────────────────────────────────────────
let stats = {
  av: {
    total_scans: 0, files_scanned: 0, processes_scanned: 0,
    threats_found: 0, threats_quarantined: 0, hash_db_size: 42381,
    pattern_count: 8743, scan_running: false, realtime_enabled: true,
    auto_kill: true, memory_scan_enabled: true,
  },
  webguard: {
    requests_inspected: 0, requests_blocked: 0, attacks_detected: 0,
    sqli_count: 0, xss_count: 0, rce_count: 0, lfi_count: 0,
    ssrf_count: 0, log4shell_count: 0, scanner_detections: 0,
    ips_banned: 0, pentest_captures: 0, rule_count: 248,
    profile: 'Aggressive', allowlist_count: 3,
    syswatch_count: 0, rate_limit_rps: 1000,
    block_threshold: 60, ban_threshold: 80,
  },
  sandbox: {
    sandbox_count: 2, proxy_port: 8080, proxy_running: true,
    total_bytes_sent: 0, total_bytes_recv: 0, total_connections: 0,
  },
  nexus: {
    events_processed: 0, sessions_created: sessions.length,
    active_sessions: rnd(0,3), incidents_created: incidents.length,
    active_incidents: incidents.filter(i => !i.auto_remediated).length,
    ioc_count: iocDb.length, ioc_hits: rnd(0,5),
    coordinated_responses: rnd(0,3), dedup_dropped: rnd(0,50),
  },
  hostguard: {
    stat_components_scanned: rnd(200,800), stat_cve_found: rnd(0,12),
    stat_remediations_applied: rnd(0,5), stat_firewall_rules_added: rnd(0,20),
    stat_processes_killed: rnd(0,3), ransomware_detections: 0,
    stat_updates_auto_installed: rnd(0,8), stat_updates_user_required: rnd(0,4),
    stat_thread_restarts: 0, stat_fire_events_published: rnd(100,2000),
    stat_honeypot_triggers: 0, stat_fim_events: rnd(0,50),
  },
  integration: {
    fim_to_av_scans: rnd(0,50), process_to_av_watches: rnd(0,100),
    tls_to_hash_checks: rnd(0,200), malware_to_bans: rnd(0,10),
    sandbox_files_scanned: rnd(0,30), nexus_escalations: rnd(0,5),
    realtime_blocks: rnd(0,20), av_to_nexus_events: rnd(0,30),
    hg_to_nexus_events: rnd(0,40), wg_to_nexus_events: rnd(0,50),
    total_cross_engine: rnd(0,200),
  },
  event_bus: { total_events: rnd(1000, 9999), capacity: 65536 },
  api: { requests_served: 0, port: PORT },
};

// Tick: update counters
setInterval(() => {
  stats.av.files_scanned         += rnd(0, 3);
  stats.av.processes_scanned     += rnd(0, 2);
  stats.av.total_scans           += 1;
  stats.webguard.requests_inspected += rnd(0, 5);
  stats.webguard.attacks_detected += rnd(0, 2);
  if (Math.random() > 0.8) stats.webguard.requests_blocked++;
  if (Math.random() > 0.9) { stats.webguard.sqli_count++; stats.webguard.attacks_detected++; }
  if (Math.random() > 0.92) stats.webguard.xss_count++;
  stats.sandbox.total_bytes_sent  += rnd(0, 1024 * 10);
  stats.sandbox.total_bytes_recv  += rnd(0, 1024 * 5);
  stats.sandbox.total_connections += rnd(0, 1);
  stats.nexus.events_processed    += rnd(0, 3);
  stats.event_bus.total_events    += rnd(0, 10);
  stats.nexus.incidents_created    = incidents.length;
  stats.nexus.active_incidents     = incidents.filter(i => !i.auto_remediated).length;
  stats.nexus.ioc_count            = iocDb.length;
  stats.webguard.ips_banned        = bannedIPs.length;
}, 3000);

// ─── CORS headers ──────────────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res, data, code = 200) {
  stats.api.requests_served++;
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

// ─── Route handler ─────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url    = req.url.split('?')[0];
  const method = req.method;
  const path   = url.startsWith(BASE) ? url.slice(BASE.length) : url;

  // ── /status ──────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/status') {
    return json(res, {
      platform: 'AegisCore Security Platform',
      version:  '1.0.0-v1-test',
      api_version: 'v1',
      uptime_seconds: uptimeSecs(),
      total_bus_events: stats.event_bus.total_events,
      api_requests: stats.api.requests_served,
      engines: {
        'WebGuard-WAF': 'Online', 'PacketGuard-AV': 'Online',
        'SmartSandbox':  'Online', 'Nexus-Correlator': 'Online',
        'HostGuard':     'Online', 'ThreatGuard':  'Online',
        'PacketAnalysis':'Online', 'HostSecurity':  'Online',
      },
    });
  }

  // ── /stats ────────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/stats') { return json(res, stats); }

  // ── /alerts ───────────────────────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/alerts') && !path.includes('/clear')) {
    const limit = parseInt(new URL('http://x' + req.url).searchParams.get('limit') || '100');
    return json(res, { alerts: alertRing.slice(-limit).reverse() });
  }
  if (method === 'POST' && path === '/alerts/clear') {
    alertRing = []; alertId = 1;
    return json(res, { status: 'cleared' });
  }

  // ── /blocks ───────────────────────────────────────────────────────────────
  if (method === 'GET'  && path === '/blocks') { return json(res, { blocks: bannedIPs }); }
  if (method === 'POST' && path === '/blocks') {
    const body = await readBody(req);
    if (body.ip && !bannedIPs.includes(body.ip)) bannedIPs.push(body.ip);
    return json(res, { status: 'banned', ip: body.ip });
  }
  if (method === 'DELETE' && path.startsWith('/blocks/')) {
    const ip = decodeURIComponent(path.slice('/blocks/'.length));
    bannedIPs = bannedIPs.filter(x => x !== ip);
    return json(res, { status: 'unbanned', ip });
  }

  // ── /incidents ─────────────────────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/incidents')) {
    const limit = parseInt(new URL('http://x' + req.url).searchParams.get('limit') || '50');
    return json(res, { incidents: incidents.slice(-limit).reverse() });
  }

  // ── /sessions ──────────────────────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/sessions')) {
    const mockSessions = incidents.map((inc, i) => ({
      session_id:       `sess-${inc.incident_id}`,
      attacker_ip:      inc.attacker_ip,
      target_ip:        inc.target_ip,
      first_event:      inc.created,
      last_event:       fmtNow(),
      kill_chain_stage: inc.kill_chain_stage,
      engine_count:     rnd(2,6),
      event_count:      rnd(5,40),
      correlated_score: inc.threat_score,
      threat_level:     inc.threat_level,
      threat_family:    inc.threat_family,
      ip_banned:        true,
      process_killed:   Math.random() > 0.5,
      network_blocked:  true,
    }));
    return json(res, { sessions: mockSessions });
  }

  // ── /ioc ──────────────────────────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/ioc')) {
    return json(res, { ioc: iocDb });
  }
  if (method === 'POST' && path === '/ioc') {
    const body = await readBody(req);
    iocDb.push({ type: body.type||'IP', value: body.value||'', threat_actor: body.actor||'Unknown', campaign: body.campaign||'Unknown', attck_tech: body.attck||'', confidence: body.confidence||50, hit_count: 0 });
    return json(res, { status: 'added' });
  }

  // ── /av/ ─────────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/av/stats') { return json(res, { av: stats.av }); }
  if (method === 'GET' && path === '/av/processes') {
    return json(res, { processes: [
      { pid: 4, name: 'System', path: 'C:\\Windows\\System32\\ntoskrnl.exe', score: 0, status: 'clean' },
      { pid: rnd(1000,9999), name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', score: 0, status: 'clean' },
      { pid: rnd(1000,9999), name: 'node.exe', path: process.execPath, score: 0, status: 'clean' },
    ]});
  }
  if (method === 'POST' && path === '/av/scan') { return json(res, { status: 'scan_started' }); }
  if (method === 'POST' && path === '/av/full-scan') {
    stats.av.scan_running = true;
    setTimeout(() => { stats.av.scan_running = false; stats.av.total_scans++; }, 10000);
    return json(res, { status: 'full_scan_started' });
  }

  // ── /waf/ ─────────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/waf/stats') { return json(res, { webguard: stats.webguard }); }
  if (method === 'GET' && path === '/waf/rules') {
    return json(res, { rules: [
      { rule_id:1, name:'SQLi Basic', description:'Detects basic SQL injection', attack_type:1, attck_technique:'T1190', severity:'critical', score_weight:80, hit_count: stats.webguard.sqli_count, check_uri:false, check_query:true, check_body:true, check_headers:false, check_cookies:true },
      { rule_id:2, name:'XSS Reflected', description:'Detects reflected XSS', attack_type:2, attck_technique:'T1059', severity:'high', score_weight:65, hit_count: stats.webguard.xss_count, check_uri:true, check_query:true, check_body:true, check_headers:false, check_cookies:true },
      { rule_id:3, name:'RCE via Shell', description:'Detects RCE command injection', attack_type:3, attck_technique:'T1059', severity:'critical', score_weight:90, hit_count: stats.webguard.rce_count, check_uri:false, check_query:true, check_body:true, check_headers:false, check_cookies:false },
      { rule_id:10, name:'Log4Shell', description:'Detects Log4Shell JNDI exploit', attack_type:10, attck_technique:'T1190', severity:'critical', score_weight:95, hit_count: stats.webguard.log4shell_count, check_uri:true, check_query:true, check_body:true, check_headers:true, check_cookies:false },
      { rule_id:11, name:'Scanner Detection', description:'Detects automated scanners', attack_type:11, attck_technique:'T1046', severity:'medium', score_weight:40, hit_count: stats.webguard.scanner_detections, check_uri:true, check_query:false, check_body:false, check_headers:true, check_cookies:false },
    ]});
  }
  if (method === 'POST' && path === '/waf/profile') {
    const body = await readBody(req);
    if (body.profile) stats.webguard.profile = body.profile;
    return json(res, { status: 'ok', profile: stats.webguard.profile });
  }
  if (method === 'GET' && path === '/waf/captures') {
    const captures = alertRing.filter(a => a.engine === 'WebGuard').slice(-30).map((a,i) => ({
      id: i+1, timestamp: a.timestamp, method: pick(['GET','POST','PUT','DELETE']),
      uri: pick(['/api/login','/admin','/search','/upload','/api/data']),
      client_ip: a.src_ip, score: rnd(40,99), blocked: a.blocked, finding_count: rnd(1,5),
    }));
    return json(res, { captures });
  }
  if (method === 'GET' && path === '/waf/allowlist') { return json(res, { allowlist: ['127.0.0.1','::1','192.168.1.1'] }); }
  if (method === 'POST' && path === '/waf/allowlist') { return json(res, { status: 'added' }); }
  if (method === 'GET' && path === '/waf/syswatch') { return json(res, { entries: [] }); }
  if (method === 'GET' && path === '/waf/report') { return json(res, { attacks_today: rnd(0,50), top_type: 'SQLi', top_ip: randomIP() }); }

  // ── /sandbox/ ─────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/sandbox/list') {
    return json(res, { sandboxes: [
      { name:'Sandbox-Alpha', state:'running', pid: rnd(1000,9999), exe:'C:\\Windows\\System32\\cmd.exe', start_time: fmtNow(), firewall_active:true, low_integrity:true, bytes_sent: rnd(0,1024*50), bytes_recv: rnd(0,1024*100), connections: rnd(0,5) },
      { name:'Sandbox-Beta',  state:'running', pid: rnd(1000,9999), exe:'C:\\Windows\\System32\\notepad.exe', start_time: fmtNow(), firewall_active:true, low_integrity:true, bytes_sent: rnd(0,1024*20), bytes_recv: rnd(0,1024*40), connections: rnd(0,2) },
    ]});
  }
  if (method === 'GET' && path === '/sandbox/proxy-logs') {
    const logs = alertRing.slice(-20).map(a => ({
      timestamp: a.timestamp, method: pick(['GET','POST','CONNECT']),
      host: `${pick(['cdn','api','downloads','static'])}.${pick(['trusted.com','cdn.net','api.io'])}`,
      port: pick([80,443,8080]), sandbox: pick(['Sandbox-Alpha','Sandbox-Beta']),
      was_blocked: a.blocked,
    }));
    return json(res, { logs });
  }
  if (method === 'GET' && path === '/sandbox/diagnostics') { return json(res, { status:'ok', proxy_reachable:true }); }

  // ── /hostguard/ ──────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/hostguard/stats') { return json(res, { hostguard: stats.hostguard }); }
  if (method === 'GET' && path === '/hostguard/threads') {
    return json(res, { threads: [
      { id:1, name:'HostGuard-Scanner',      alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:2, name:'CVE-Checker',            alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:3, name:'UpdateManager',          alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:4, name:'Honeypot-Monitor',       alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:5, name:'RansomwareShield',       alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:6, name:'FIM-Watcher',            alive:true,  last_heartbeat_age_s: rnd(0,9),  restart_count:0 },
      { id:7, name:'Heartbeat-Monitor',      alive:true,  last_heartbeat_age_s: rnd(0,4),  restart_count:0 },
    ]});
  }
  if (method === 'GET' && path === '/hostguard/components') {
    const components = [
      { db_id:1, name:'OpenSSL', version:'3.0.2', type:'Library', os_info:'Windows 11', first_seen: fmtNow(), last_seen: fmtNow(), needs_cve_check:true, needs_update_check:true },
      { db_id:2, name:'Node.js', version:process.version.slice(1), type:'Runtime', os_info:'Windows 11', first_seen: fmtNow(), last_seen: fmtNow(), needs_cve_check:false, needs_update_check:false },
      { db_id:3, name:'Microsoft Edge', version:'121.0.0', type:'Browser', os_info:'Windows 11', first_seen: fmtNow(), last_seen: fmtNow(), needs_cve_check:false, needs_update_check:true },
      { db_id:4, name:'Python 3', version:'3.11.2', type:'Runtime', os_info:'Windows 11', first_seen: fmtNow(), last_seen: fmtNow(), needs_cve_check:true, needs_update_check:false },
      { db_id:5, name:'curl', version:'8.1.2', type:'Tool', os_info:'Windows 11', first_seen: fmtNow(), last_seen: fmtNow(), needs_cve_check:false, needs_update_check:false },
    ];
    return json(res, { components });
  }
  if (method === 'GET' && path === '/hostguard/cves') {
    return json(res, {
      total_cve_found: stats.hostguard.stat_cve_found,
      total_checks_done: stats.hostguard.stat_components_scanned,
      remediations_applied: stats.hostguard.stat_remediations_applied,
      recent_remediations: stats.hostguard.stat_cve_found > 0 ? [
        { db_id:1, component:'OpenSSL', risk_level:'high', cve_list:'CVE-2023-0215,CVE-2023-0216', status:'remediated', executed_at: fmtNow() },
      ] : [],
    });
  }
  if (method === 'GET' && path === '/hostguard/updates') {
    return json(res, {
      auto_installed: stats.hostguard.stat_updates_auto_installed,
      user_required:  stats.hostguard.stat_updates_user_required,
      pending: stats.hostguard.stat_updates_user_required > 0 ? [
        { component:'OpenSSL', type:'security', current_version:'3.0.2', latest_version:'3.2.1', update_safe:true, status:'pending_approval' },
      ] : [],
    });
  }
  if (method === 'GET' && path === '/hostguard/honeypots') {
    return json(res, { count:3, ransomware_lockdown:false, files:[
      { path:'C:\\Decoy\\documents\\salary.xlsx', size:24576, active:true, created: fmtNow(), sha256:'deadbeefcafe0102030405060708090a0b0c0d0e0f' },
      { path:'C:\\Decoy\\backup\\passwords.txt', size:512, active:true, created: fmtNow(), sha256:'0102030405060708090a0b0c0d0e0f101112131415' },
    ]});
  }
  if (method === 'GET' && path === '/hostguard/ransomware') {
    return json(res, { total_detections:0, processes_killed:0, currently_locked_down:false, honeypot_count:3 });
  }
  if (method === 'POST' && path === '/hostguard/scan') { return json(res, { status:'scan_initiated' }); }

  // ── /integration/stats ────────────────────────────────────────────────────
  if (method === 'GET' && path === '/integration/stats') { return json(res, { integration: stats.integration }); }

  // ── /events/bus ─────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/events/bus') { return json(res, { total_events: stats.event_bus.total_events, capacity: stats.event_bus.capacity }); }

  // ── /system/autostart ──────────────────────────────────────────────────
  if (method === 'POST' && path === '/system/autostart') { return json(res, { status:'ok' }); }

  // ── 404 ──────────────────────────────────────────────────────────────────
  json(res, { error:`Not Found: ${method} ${path}` }, 404);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[AegisCore Mock Backend] v1 running on http://127.0.0.1:${PORT}/api/v1/`);
  console.log(`[AegisCore Mock Backend] Simulating all 8 engine endpoints`);
  console.log(`[AegisCore Mock Backend] Alerts generated every 8s | Incidents every 30s`);
  console.log(`[AegisCore Mock Backend] Ready for frontend connection`);
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[Error] Port ${PORT} is already in use — real backend may be running`);
    process.exit(0);
  }
});
