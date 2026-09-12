/**
 * AegisCore — Reports Page
 * Generates reports from live backend data.
 * No mock data. No emoji.
 */
import React, { useState } from 'react';
import { FileText, Download, RefreshCw, BarChart3, Shield, Activity, AlertTriangle, CheckCircle } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { AegisLiveData } from '../api/useAegisData';

interface ReportsProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success' | 'info' | 'warning' | 'error') => void;
}

function fmtBytes(b: number): string {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ') || '< 1m';
}

export const Reports: React.FC<ReportsProps> = ({ liveData, addToast }) => {
  const [exporting, setExporting] = useState(false);

  const exportJSON = () => {
    if (!liveData.connected) { addToast('Backend offline — cannot generate report', 'error'); return; }
    setExporting(true);
    const report = {
      generated_at: new Date().toISOString(),
      platform:     liveData.status?.platform,
      version:      liveData.status?.version,
      uptime_s:     liveData.status?.uptime_seconds,
      engines:      liveData.status?.engines,
      summary: {
        total_alerts:    liveData.alerts.length,
        critical_alerts: liveData.alerts.filter(a => a.severity === 'critical').length,
        blocked_alerts:  liveData.alerts.filter(a => a.blocked).length,
        active_incidents:liveData.incidents.filter(i => !i.auto_remediated).length,
        total_sessions:  liveData.sessions.length,
        ioc_count:       liveData.ioc.length,
        banned_ips:      liveData.blocks.length,
      },
      av:       liveData.stats?.av,
      webguard: liveData.stats?.webguard,
      nexus:    liveData.stats?.nexus,
      hostguard:liveData.stats?.hostguard,
      sandbox:  liveData.stats?.sandbox,
      integration: liveData.stats?.integration,
      top_alerts: liveData.alerts.slice(0, 20),
      incidents:  liveData.incidents.slice(0, 10),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `aegiscore-report-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExporting(false);
    addToast('Report exported successfully', 'success');
  };

  const stats = liveData.stats;
  const status = liveData.status;

  return (
    <div className="page-container animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <FileText size={20} style={{ color: 'hsl(var(--accent-color))' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Security Reports</h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={() => liveData.refresh()} variant="secondary"><RefreshCw size={14} /> Refresh Data</Button>
          <Button onClick={exportJSON} disabled={exporting || !liveData.connected}>
            <Download size={14} /> {exporting ? 'Exporting...' : 'Export JSON'}
          </Button>
        </div>
      </div>

      {!liveData.connected && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px', color: '#f97316' }}>
            <AlertTriangle size={18} />
            <span style={{ fontSize: '0.85rem' }}>Backend offline — report data may be stale or unavailable.</span>
          </div>
        </Card>
      )}

      {/* Platform Summary */}
      <Card style={{ marginTop: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
          <Shield size={16} style={{ color: 'hsl(var(--accent-color))' }} />
          <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>Platform Summary</span>
          {status && <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))', marginLeft: 8 }}>Uptime: {fmtUptime(status.uptime_seconds)}</span>}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
          {[
            { label: 'Platform', value: status?.platform ?? '—' },
            { label: 'Version', value: status?.version ?? '—' },
            { label: 'API Requests', value: status?.api_requests?.toLocaleString() ?? '—' },
            { label: 'Total Bus Events', value: stats?.event_bus.total_events?.toLocaleString() ?? '—' },
            { label: 'Alerts in Ring', value: liveData.alerts.length.toLocaleString() },
            { label: 'Connected', value: liveData.connected ? 'Yes' : 'No' },
          ].map(({ label, value }) => (
            <div key={label} style={{ padding: '10px 14px', background: 'hsl(var(--bg-secondary))', borderRadius: 8 }}>
              <div style={{ fontSize: '0.72rem', color: 'hsl(var(--text-secondary))', marginBottom: 2 }}>{label}</div>
              <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{value}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Security Report */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
        {/* Alert Summary */}
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
            <AlertTriangle size={16} style={{ color: '#ef4444' }} />
            <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>Alert Summary</span>
          </div>
          {[
            { label: 'Total Alerts',    value: liveData.alerts.length,                              color: '#3b82f6' },
            { label: 'Critical',        value: liveData.alerts.filter(a => a.severity === 'critical').length, color: '#ef4444' },
            { label: 'High',            value: liveData.alerts.filter(a => a.severity === 'high').length,    color: '#f97316' },
            { label: 'Blocked',         value: liveData.alerts.filter(a => a.blocked).length,       color: '#22c55e' },
            { label: 'IPs Banned',      value: liveData.blocks.length,                               color: '#8b5cf6' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid hsl(var(--border-primary))' }}>
              <span style={{ fontSize: '0.82rem', color: 'hsl(var(--text-secondary))' }}>{label}</span>
              <span style={{ fontWeight: 700, color }}>{value}</span>
            </div>
          ))}
        </Card>

        {/* Engine Stats */}
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
            <Activity size={16} style={{ color: 'hsl(var(--accent-color))' }} />
            <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>Engine Performance</span>
          </div>
          {[
            { label: 'WAF Requests Inspected', value: stats?.webguard.requests_inspected.toLocaleString() ?? '—' },
            { label: 'WAF Attacks Detected',   value: stats?.webguard.attacks_detected.toLocaleString() ?? '—' },
            { label: 'AV Files Scanned',        value: stats?.av.files_scanned.toLocaleString() ?? '—' },
            { label: 'AV Threats Found',        value: stats?.av.threats_found.toLocaleString() ?? '—' },
            { label: 'Nexus Incidents',          value: stats?.nexus.incidents_created.toLocaleString() ?? '—' },
            { label: 'HG CVEs Found',            value: stats?.hostguard.stat_cve_found.toLocaleString() ?? '—' },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid hsl(var(--border-primary))' }}>
              <span style={{ fontSize: '0.82rem', color: 'hsl(var(--text-secondary))' }}>{label}</span>
              <span style={{ fontWeight: 700 }}>{value}</span>
            </div>
          ))}
        </Card>
      </div>

      {/* Recent Incidents */}
      {liveData.incidents.length > 0 && (
        <Card style={{ marginTop: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
            <BarChart3 size={16} style={{ color: 'hsl(var(--accent-color))' }} />
            <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>Recent Incidents ({liveData.incidents.length})</span>
          </div>
          {liveData.incidents.slice(0, 5).map(inc => (
            <div key={inc.incident_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid hsl(var(--border-primary))' }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.83rem' }}>{inc.title}</div>
                <div style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{inc.attacker_ip} — {inc.threat_family}</div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: '0.82rem', color: inc.threat_score >= 80 ? '#ef4444' : inc.threat_score >= 60 ? '#f97316' : '#eab308' }}>
                  Score: {inc.threat_score}
                </span>
                {inc.auto_remediated && <CheckCircle size={14} color="#22c55e" />}
              </div>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
};
