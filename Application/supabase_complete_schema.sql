-- =========================================================================
-- KAEVEX MOBILE SOC - COMPLETE SUPABASE CLOUD DATABASE SCHEMA
-- Project URL: https://lqvijkatveozunxzlaid.supabase.co
-- Run this in the Supabase Dashboard -> SQL Editor
-- =========================================================================

-- 1. Mobile Activity & Telemetry Logs
CREATE TABLE IF NOT EXISTS public.mobile_activity_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    user_email TEXT,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT,
    device_info TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.mobile_activity_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on mobile_activity_logs" ON public.mobile_activity_logs FOR ALL USING (true) WITH CHECK (true);

-- 2. Multi-Server Cluster Nodes
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
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip, port)
);
ALTER TABLE public.cluster_nodes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on cluster_nodes" ON public.cluster_nodes FOR ALL USING (true) WITH CHECK (true);

-- 3. Security Threat Alerts
CREATE TABLE IF NOT EXISTS public.security_alerts (
    id BIGSERIAL PRIMARY KEY,
    time TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    is_resolved BOOLEAN NOT NULL DEFAULT false,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.security_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on security_alerts" ON public.security_alerts FOR ALL USING (true) WITH CHECK (true);

-- 4. Persistent AI Copilot Conversations
CREATE TABLE IF NOT EXISTS public.ai_chat_messages (
    id BIGSERIAL PRIMARY KEY,
    message_uuid TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL, -- 'USER' or 'SOC_AGENT'
    text TEXT NOT NULL,
    team TEXT NOT NULL DEFAULT 'blue',
    timestamp TEXT NOT NULL,
    action_type TEXT,
    action_label TEXT,
    action_target TEXT,
    execution_result TEXT,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.ai_chat_messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on ai_chat_messages" ON public.ai_chat_messages FOR ALL USING (true) WITH CHECK (true);

-- 5. Mobile Device Posture & Hardware Telemetry
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
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.device_telemetry ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on device_telemetry" ON public.device_telemetry FOR ALL USING (true) WITH CHECK (true);

-- 6. CVE Inventory & Remediation Matrix
CREATE TABLE IF NOT EXISTS public.cve_records (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss NUMERIC(3, 1) NOT NULL,
    affected_software TEXT NOT NULL,
    is_patched BOOLEAN NOT NULL DEFAULT false,
    can_auto_remediate BOOLEAN NOT NULL DEFAULT false,
    remediated_at TIMESTAMPTZ
);
ALTER TABLE public.cve_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on cve_records" ON public.cve_records FOR ALL USING (true) WITH CHECK (true);

-- 7. Bootkit Forensic Audit Reports
CREATE TABLE IF NOT EXISTS public.boot_audit_reports (
    id BIGSERIAL PRIMARY KEY,
    status TEXT NOT NULL,
    secure_boot_enabled BOOLEAN NOT NULL,
    test_signing_disabled BOOLEAN NOT NULL,
    mbr_signature_valid BOOLEAN NOT NULL,
    core_binaries_verified INTEGER NOT NULL,
    audit_json JSONB,
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.boot_audit_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on boot_audit_reports" ON public.boot_audit_reports FOR ALL USING (true) WITH CHECK (true);

-- 8. Operator Configuration & Preferences
CREATE TABLE IF NOT EXISTS public.operator_settings (
    user_email TEXT PRIMARY KEY,
    biometrics_enabled BOOLEAN NOT NULL DEFAULT true,
    refresh_interval_sec INTEGER NOT NULL DEFAULT 5,
    request_timeout_sec BIGINT NOT NULL DEFAULT 5,
    together_api_key TEXT,
    ai_model TEXT DEFAULT 'deepseek-ai/DeepSeek-V4-Pro-0813',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.operator_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all operations for anon on operator_settings" ON public.operator_settings FOR ALL USING (true) WITH CHECK (true);
