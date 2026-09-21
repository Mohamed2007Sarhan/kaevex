-- ===========================================================================
-- Kaevex Security Platform v1.0 — Supabase Cloud Architecture Schema
-- Realtime Multi-Device Synchronization & SOC Defense Central Store
-- Project URL: https://lqvijkatveozunxzlaid.supabase.co
-- ===========================================================================

-- 1. CONNECTED DEVICES & TOPOLOGY (Real dynamic hardware/network telemetry)
CREATE TABLE IF NOT EXISTS public.devices (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    hostname TEXT UNIQUE NOT NULL,
    os_version TEXT NOT NULL,
    primary_ip TEXT NOT NULL,
    active_connections INT DEFAULT 0,
    threat_score INT DEFAULT 0,
    security_profile TEXT DEFAULT 'Enterprise SOC',
    status TEXT DEFAULT 'ONLINE', -- ONLINE, ISOLATED, OFFLINE
    last_seen TIMESTAMPTZ DEFAULT now()
);

-- 2. REALTIME TELEMETRY SNAPSHOTS (Live kernel metrics: CPU, RAM, Sockets)
CREATE TABLE IF NOT EXISTS public.telemetry_snapshots (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    cpu_usage INT DEFAULT 0,
    memory_usage_mb INT DEFAULT 0,
    total_memory_mb INT DEFAULT 0,
    active_connections INT DEFAULT 0,
    inbound_kbps INT DEFAULT 0,
    outbound_kbps INT DEFAULT 0,
    waf_blocked_requests INT DEFAULT 0,
    threat_score INT DEFAULT 0,
    recorded_at TIMESTAMPTZ DEFAULT now()
);

-- 3. LIVE SECURITY ALERTS (Real defense alerts from all 15 engines)
CREATE TABLE IF NOT EXISTS public.security_alerts (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    engine TEXT NOT NULL,         -- 'WebGuard WAF', 'Antivirus', 'RansomShield', 'BootkitAudit', etc.
    severity TEXT NOT NULL,       -- 'CRITICAL', 'HIGH', 'WARNING', 'INFO'
    title TEXT NOT NULL,
    src_ip TEXT DEFAULT 'Local',
    payload TEXT,
    attck_tag TEXT DEFAULT 'N/A', -- 'ATT&CK:T1059', 'ATT&CK:T1486', etc.
    is_blocked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. VULNERABILITIES & AUTONOMOUS CVE TRACKER (Real discovered & patched flaws)
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    software_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    severity TEXT DEFAULT 'HIGH', -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    cvss_score NUMERIC(3,1) DEFAULT 7.5,
    status TEXT DEFAULT 'DISCOVERED', -- 'DISCOVERED', 'MITIGATED', 'PATCHED'
    action_taken TEXT,
    remediated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (hostname, cve_id, software_name)
);

-- 5. AI SOC ANALYST CONVERSATIONS & AUDIT LOGS (Real queries & responses)
CREATE TABLE IF NOT EXISTS public.ai_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    model TEXT DEFAULT 'deepseek-ai/DeepSeek-V4-Pro-0813',
    threat_level INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 6. REMOTE DEFENSE ACTIONS (Live Bi-directional command loop: Mobile <-> Desktop)
CREATE TABLE IF NOT EXISTS public.action_logs (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    action_type TEXT NOT NULL,    -- 'EMERGENCY_LOCKDOWN', 'DISENGAGE_LOCKDOWN', 'TERMINATE_PROCESS', 'DEEP_SCAN', 'KILL_SANDBOX'
    target TEXT DEFAULT '',
    initiated_by TEXT DEFAULT 'SOC_CONSOLE', -- 'MOBILE_APP', 'DESKTOP_GUI', 'AUTONOMOUS_AGENT'
    status TEXT DEFAULT 'PENDING',-- 'PENDING', 'COMPLETED', 'FAILED'
    details TEXT,
    executed_at TIMESTAMPTZ DEFAULT now()
);

-- 7. TEAM COLLABORATION & ROLE DIRECTIONS (Synced team accounts & clearance)
CREATE TABLE IF NOT EXISTS public.team_members (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,           -- 'SOC_DIRECTOR', 'SECURITY_ANALYST', 'PEN_TESTER', 'DEVSECOPS'
    clearance TEXT DEFAULT 'TIER_3',-- 'TIER_1', 'TIER_2', 'TIER_3'
    direction TEXT,               -- 'Threat Hunting', 'Rootkit Defense', 'Incident Response'
    status TEXT DEFAULT 'ACTIVE',
    last_active TIMESTAMPTZ DEFAULT now()
);

-- 8. AUDITED SOFTWARE INVENTORY & SUSPICIOUS BINARIES (Real host software scan)
CREATE TABLE IF NOT EXISTS public.audited_software (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    app_name TEXT NOT NULL,
    version TEXT,
    publisher TEXT,
    is_dangerous BOOLEAN DEFAULT false,
    threat_tag TEXT DEFAULT 'BENIGN',
    quarantined BOOLEAN DEFAULT false,
    audited_at TIMESTAMPTZ DEFAULT now()
);

-- 9. BOOTKIT & LOW-LEVEL HARDWARE FIRMWARE AUDITS (Real MBR, CatRoot & Driver audits)
CREATE TABLE IF NOT EXISTS public.bootkit_audits (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    integrity_score INT DEFAULT 100,
    secure_boot BOOLEAN DEFAULT true,
    test_signing BOOLEAN DEFAULT false,
    mbr_valid BOOLEAN DEFAULT true,
    system_files_audited INT DEFAULT 0,
    compromised_files INT DEFAULT 0,
    rogue_services INT DEFAULT 0,
    audited_at TIMESTAMPTZ DEFAULT now()
);

-- ===========================================================================
-- REALTIME SUBSCRIPTIONS
-- ===========================================================================
ALTER PUBLICATION supabase_realtime ADD TABLE public.security_alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE public.devices;
ALTER PUBLICATION supabase_realtime ADD TABLE public.telemetry_snapshots;
ALTER PUBLICATION supabase_realtime ADD TABLE public.action_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE public.vulnerabilities;
ALTER PUBLICATION supabase_realtime ADD TABLE public.ai_audit_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE public.team_members;
ALTER PUBLICATION supabase_realtime ADD TABLE public.bootkit_audits;
ALTER PUBLICATION supabase_realtime ADD TABLE public.audited_software;

-- ===========================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Allows both Anon client (Mobile/Desktop) and Authenticated users full access
-- ===========================================================================
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.action_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audited_software ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bootkit_audits ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on devices" ON public.devices FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on telemetry_snapshots" ON public.telemetry_snapshots FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on security_alerts" ON public.security_alerts FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on vulnerabilities" ON public.vulnerabilities FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on ai_audit_logs" ON public.ai_audit_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on action_logs" ON public.action_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on team_members" ON public.team_members FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on audited_software" ON public.audited_software FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on bootkit_audits" ON public.bootkit_audits FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
