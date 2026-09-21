-- ===========================================================================
-- Kaevex Security Platform v1.0 — Unified Supabase Cloud Architecture Schema
-- Realtime Multi-Device Synchronization & SOC Defense Central Store
-- Project URL: https://lqvijkatveozunxzlaid.supabase.co
-- Supports both Desktop SOC (kaevex.exe) and Mobile SOC (com.kaevex.fireware)
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
    hostname TEXT DEFAULT 'LocalHost',
    time TEXT,
    engine TEXT NOT NULL DEFAULT 'Kaevex',
    severity TEXT NOT NULL DEFAULT 'INFO',
    source TEXT DEFAULT 'LocalHost',
    message TEXT,
    title TEXT,
    src_ip TEXT DEFAULT 'Local',
    payload TEXT,
    attck_tag TEXT DEFAULT 'N/A',
    is_blocked BOOLEAN DEFAULT false,
    is_resolved BOOLEAN DEFAULT false,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. VULNERABILITIES & AUTONOMOUS CVE TRACKER (Real discovered & patched flaws)
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    software_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    severity TEXT DEFAULT 'HIGH',
    cvss_score NUMERIC(3,1) DEFAULT 7.5,
    status TEXT DEFAULT 'DISCOVERED',
    action_taken TEXT,
    remediated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(hostname, cve_id)
);

-- 5. AI SOC COPILOT AUDIT LOGS & ACTIONS
CREATE TABLE IF NOT EXISTS public.ai_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    analyst_model TEXT NOT NULL,
    prompt_query TEXT NOT NULL,
    response_summary TEXT NOT NULL,
    recommended_action TEXT,
    confidence_score INT DEFAULT 95,
    dispatched_at TIMESTAMPTZ DEFAULT now()
);

-- 6. REMOTE DEFENSE ACTIONS & COMMAND DISPATCH
CREATE TABLE IF NOT EXISTS public.action_logs (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    operator TEXT NOT NULL DEFAULT 'SOC Operator',
    action_name TEXT NOT NULL,
    action_target TEXT,
    result TEXT NOT NULL,
    status TEXT DEFAULT 'EXECUTED',
    timestamp TIMESTAMPTZ DEFAULT now()
);

-- 7. CYBER TEAM MEMBERS & OPERATORS
CREATE TABLE IF NOT EXISTS public.team_members (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'SOC Analyst',
    assigned_team TEXT NOT NULL DEFAULT 'Purple Team',
    status TEXT DEFAULT 'ACTIVE',
    last_login TIMESTAMPTZ DEFAULT now()
);

-- 8. AUDITED SOFTWARE INVENTORY
CREATE TABLE IF NOT EXISTS public.audited_software (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    software_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    publisher TEXT DEFAULT 'Unknown',
    install_date TEXT,
    vulnerability_count INT DEFAULT 0,
    last_audited TIMESTAMPTZ DEFAULT now(),
    UNIQUE(hostname, software_name)
);

-- 9. DEEP BOOTKIT & ROOTKIT AUDIT RECORDS
CREATE TABLE IF NOT EXISTS public.bootkit_audits (
    id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL,
    uefi_secureboot TEXT NOT NULL,
    bcd_testsigning TEXT NOT NULL,
    esp_signature TEXT NOT NULL,
    mbr_signature TEXT NOT NULL,
    overall_trust_score INT NOT NULL,
    system_files_audited INT DEFAULT 0,
    compromised_files INT DEFAULT 0,
    rogue_services INT DEFAULT 0,
    audited_at TIMESTAMPTZ DEFAULT now()
);

-- 10. MOBILE ACTIVITY & TELEMETRY LOGS
CREATE TABLE IF NOT EXISTS public.mobile_activity_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    user_email TEXT,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT,
    device_info TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 11. MULTI-SERVER CLUSTER NODES
CREATE TABLE IF NOT EXISTS public.cluster_nodes (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 9009,
    role TEXT NOT NULL DEFAULT 'Master',
    status TEXT NOT NULL DEFAULT 'ONLINE',
    ping_ms INTEGER NOT NULL DEFAULT 0,
    threats INTEGER NOT NULL DEFAULT 0,
    is_locked BOOLEAN NOT NULL DEFAULT false,
    token TEXT,
    user_email TEXT,
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(ip, port)
);

-- 12. PERSISTENT AI COPILOT CONVERSATIONS (Mobile & Multi-Agent)
CREATE TABLE IF NOT EXISTS public.ai_chat_messages (
    id BIGSERIAL PRIMARY KEY,
    message_uuid TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    text TEXT NOT NULL,
    team TEXT NOT NULL DEFAULT 'blue',
    timestamp TEXT NOT NULL,
    action_type TEXT,
    action_label TEXT,
    action_target TEXT,
    execution_result TEXT,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 13. MOBILE DEVICE POSTURE & HARDWARE TELEMETRY
CREATE TABLE IF NOT EXISTS public.device_telemetry (
    id BIGSERIAL PRIMARY KEY,
    user_email TEXT,
    device_model TEXT NOT NULL,
    battery_pct INTEGER NOT NULL,
    is_charging BOOLEAN NOT NULL,
    available_ram_mb BIGINT NOT NULL,
    total_ram_mb BIGINT NOT NULL,
    free_storage_gb NUMERIC(10, 2) NOT NULL,
    local_ip TEXT NOT NULL,
    connection_type TEXT NOT NULL,
    is_rooted BOOLEAN NOT NULL DEFAULT false,
    is_adb_active BOOLEAN NOT NULL DEFAULT false,
    integrity_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 14. CVE INVENTORY & REMEDIATION MATRIX
CREATE TABLE IF NOT EXISTS public.cve_records (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss NUMERIC(3, 1) NOT NULL,
    affected_software TEXT NOT NULL,
    is_patched BOOLEAN NOT NULL DEFAULT false,
    can_auto_remediate BOOLEAN NOT NULL DEFAULT false,
    remediated_at TIMESTAMPTZ DEFAULT now()
);

-- 15. BOOTKIT FORENSIC AUDIT REPORTS
CREATE TABLE IF NOT EXISTS public.boot_audit_reports (
    id BIGSERIAL PRIMARY KEY,
    status TEXT NOT NULL,
    secure_boot_enabled BOOLEAN NOT NULL,
    test_signing_disabled BOOLEAN NOT NULL,
    mbr_signature_valid BOOLEAN NOT NULL,
    core_binaries_verified INTEGER NOT NULL,
    audit_json JSONB,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 16. OPERATOR CONFIGURATION & PREFERENCES
CREATE TABLE IF NOT EXISTS public.operator_settings (
    user_email TEXT PRIMARY KEY,
    biometrics_enabled BOOLEAN NOT NULL DEFAULT true,
    refresh_interval_sec INTEGER NOT NULL DEFAULT 5,
    request_timeout_sec BIGINT NOT NULL DEFAULT 5,
    together_api_key TEXT,
    ai_model TEXT DEFAULT 'deepseek-ai/DeepSeek-V4-Pro-0813',
    updated_at TIMESTAMPTZ DEFAULT now()
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
ALTER PUBLICATION supabase_realtime ADD TABLE public.mobile_activity_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE public.cluster_nodes;
ALTER PUBLICATION supabase_realtime ADD TABLE public.ai_chat_messages;
ALTER PUBLICATION supabase_realtime ADD TABLE public.device_telemetry;
ALTER PUBLICATION supabase_realtime ADD TABLE public.cve_records;
ALTER PUBLICATION supabase_realtime ADD TABLE public.boot_audit_reports;
ALTER PUBLICATION supabase_realtime ADD TABLE public.operator_settings;

-- ===========================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
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
ALTER TABLE public.mobile_activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cluster_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.boot_audit_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operator_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all on devices" ON public.devices FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on telemetry_snapshots" ON public.telemetry_snapshots FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on security_alerts" ON public.security_alerts FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on vulnerabilities" ON public.vulnerabilities FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on ai_audit_logs" ON public.ai_audit_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on action_logs" ON public.action_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on team_members" ON public.team_members FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on audited_software" ON public.audited_software FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on bootkit_audits" ON public.bootkit_audits FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on mobile_activity_logs" ON public.mobile_activity_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on cluster_nodes" ON public.cluster_nodes FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on ai_chat_messages" ON public.ai_chat_messages FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on device_telemetry" ON public.device_telemetry FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on cve_records" ON public.cve_records FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on boot_audit_reports" ON public.boot_audit_reports FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Allow all on operator_settings" ON public.operator_settings FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
