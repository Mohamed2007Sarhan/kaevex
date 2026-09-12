/**
 * AegisCore — Extended live data hook
 * Polls ALL backend endpoints every 5s and provides typed data
 * to every page. No mock data. No fallbacks.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  api,
  AllStats,
  APIAlert,
  NexusIncident,
  NexusSession,
  IOCEntry,
  PlatformStatus,
  WatchedProcess,
  SandboxInstance,
  HostGuardThread,
  SoftwareComponent,
  WAFRule,
} from './client';

export interface WafCapture {
  id: number;
  timestamp: string;
  method: string;
  uri: string;
  client_ip: string;
  score: number;
  blocked: boolean;
  finding_count: number;
}

export interface ProxyLogEntry {
  timestamp: string;
  method: string;
  host: string;
  port: number;
  sandbox: string;
  was_blocked: boolean;
}

export interface CVEReport {
  total_cve_found: number;
  total_checks_done: number;
  remediations_applied: number;
  recent_remediations: {
    db_id: number;
    component: string;
    risk_level: string;
    cve_list: string;
    status: string;
    executed_at: string;
  }[];
}

export interface UpdateReport {
  auto_installed: number;
  user_required: number;
  pending: {
    component: string;
    type: string;
    current_version: string;
    latest_version: string;
    update_safe: boolean;
    status: string;
  }[];
}

export interface HoneypotReport {
  count: number;
  ransomware_lockdown: boolean;
  files: { path: string; size: number; active: boolean; created: string; sha256: string }[];
}

export interface RansomwareReport {
  total_detections: number;
  processes_killed: number;
  currently_locked_down: boolean;
  honeypot_count: number;
}

export interface AegisLiveData {
  // Core
  status:      PlatformStatus | null;
  stats:       AllStats | null;
  // Alerts & Blocks
  alerts:      APIAlert[];
  blocks:      string[];
  // Nexus
  incidents:   NexusIncident[];
  sessions:    NexusSession[];
  ioc:         IOCEntry[];
  // AV
  processes:   WatchedProcess[];
  // WAF
  wafCaptures: WafCapture[];
  wafRules:    WAFRule[];
  // Sandbox
  sandboxList: SandboxInstance[];
  proxyLogs:   ProxyLogEntry[];
  // HostGuard
  hgThreads:    HostGuardThread[];
  hgComponents: SoftwareComponent[];
  cveReport:    CVEReport | null;
  updateReport: UpdateReport | null;
  honeypots:    HoneypotReport | null;
  ransomware:   RansomwareReport | null;
  // Meta
  loading:    boolean;
  error:      string | null;
  connected:  boolean;
  lastUpdate: Date | null;
  refresh:    () => void;
}

const POLL_MS = 5000;

export function useAegisData(): AegisLiveData {
  const [status,       setStatus]       = useState<PlatformStatus | null>(null);
  const [stats,        setStats]        = useState<AllStats | null>(null);
  const [alerts,       setAlerts]       = useState<APIAlert[]>([]);
  const [blocks,       setBlocks]       = useState<string[]>([]);
  const [incidents,    setIncidents]    = useState<NexusIncident[]>([]);
  const [sessions,     setSessions]     = useState<NexusSession[]>([]);
  const [ioc,          setIoc]          = useState<IOCEntry[]>([]);
  const [processes,    setProcesses]    = useState<WatchedProcess[]>([]);
  const [wafCaptures,  setWafCaptures]  = useState<WafCapture[]>([]);
  const [wafRules,     setWafRules]     = useState<WAFRule[]>([]);
  const [sandboxList,  setSandboxList]  = useState<SandboxInstance[]>([]);
  const [proxyLogs,    setProxyLogs]    = useState<ProxyLogEntry[]>([]);
  const [hgThreads,    setHgThreads]    = useState<HostGuardThread[]>([]);
  const [hgComponents, setHgComponents] = useState<SoftwareComponent[]>([]);
  const [cveReport,    setCveReport]    = useState<CVEReport | null>(null);
  const [updateReport, setUpdateReport] = useState<UpdateReport | null>(null);
  const [honeypots,    setHoneypots]    = useState<HoneypotReport | null>(null);
  const [ransomware,   setRansomware]   = useState<RansomwareReport | null>(null);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState<string | null>(null);
  const [connected,    setConnected]    = useState(false);
  const [lastUpdate,   setLastUpdate]   = useState<Date | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      // Fetch all endpoints concurrently
      const [
        s, st, al, bk, inc, sess, iocData,
        proc, captures, rules,
        sbList, plogs,
        threads, components, cves, updates, hp, rsw
      ] = await Promise.all([
        api.status(),
        api.stats(),
        api.alerts(200),
        api.blocks(),
        api.incidents(100),
        api.sessions(50),
        api.ioc(200),
        api.avProcesses(),
        api.wafCaptures(100),
        api.wafRules(100),
        api.sandboxList(),
        api.sandboxProxyLogs(100),
        api.hostguardThreads(),
        api.hostguardComponents(200),
        api.hostguardCVEs(),
        api.hostguardUpdates(),
        api.hostguardHoneypots(),
        api.hostguardRansomware(),
      ]);

      setStatus(s);
      setStats(st);
      setAlerts(al.alerts         ?? []);
      setBlocks(bk.blocks         ?? []);
      setIncidents(inc.incidents  ?? []);
      setSessions(sess.sessions   ?? []);
      setIoc(iocData.ioc          ?? []);
      setProcesses(proc.processes ?? []);
      setWafCaptures((captures as any).captures ?? []);
      setWafRules((rules as any).rules           ?? []);
      setSandboxList(sbList.sandboxes            ?? []);
      setProxyLogs((plogs as any).logs           ?? []);
      setHgThreads(threads.threads               ?? []);
      setHgComponents(components.components      ?? []);
      setCveReport(cves    as CVEReport);
      setUpdateReport(updates as UpdateReport);
      setHoneypots(hp      as HoneypotReport);
      setRansomware(rsw    as RansomwareReport);
      setConnected(true);
      setError(null);
      setLastUpdate(new Date());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Connection failed');
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    timerRef.current = setInterval(fetchAll, POLL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [fetchAll]);

  return {
    status, stats, alerts, blocks,
    incidents, sessions, ioc,
    processes, wafCaptures, wafRules,
    sandboxList, proxyLogs,
    hgThreads, hgComponents,
    cveReport, updateReport, honeypots, ransomware,
    loading, error, connected, lastUpdate,
    refresh: fetchAll,
  };
}
