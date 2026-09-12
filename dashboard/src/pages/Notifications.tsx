/**
 * AegisCore — Notifications Page
 * Shows live alerts from the backend ring buffer.
 * No mock data. No emoji.
 */
import React, { useState } from 'react';
import { Bell, BellOff, CheckCircle, XCircle, AlertTriangle, Info, RefreshCw, Filter } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Table } from '../components/UI/Table';
import { Button } from '../components/UI/Button';
import { AegisLiveData } from '../api/useAegisData';
import { api } from '../api/client';

interface NotificationsProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success' | 'info' | 'warning' | 'error') => void;
  alerts?: any;
  setAlerts?: any;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SeverityBadge: React.FC<{ s: string }> = ({ s }) => {
  const color =
    s === 'critical' ? '#ef4444' :
    s === 'high'     ? '#f97316' :
    s === 'medium'   ? '#eab308' : '#6b7280';
  return (
    <span style={{
      padding: '2px 8px', borderRadius: 4,
      fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase',
      background: `${color}22`, color, border: `1px solid ${color}55`,
    }}>{s}</span>
  );
};

export const Notifications: React.FC<NotificationsProps> = ({ liveData, addToast }) => {
  const [filter, setFilter]         = useState<'all' | 'critical' | 'high' | 'unblocked'>('all');
  const [dismissed, setDismissed]   = useState<Set<number>>(new Set());
  const [clearing, setClearing]     = useState(false);

  const alerts = liveData.alerts.filter(a => !dismissed.has(a.id));

  const filtered = alerts.filter(a => {
    if (filter === 'critical')  return a.severity === 'critical';
    if (filter === 'high')      return a.severity === 'high';
    if (filter === 'unblocked') return !a.blocked;
    return true;
  }).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));

  const dismiss = (id: number) => {
    setDismissed(prev => new Set([...prev, id]));
    addToast('Alert dismissed', 'info');
  };

  const clearAll = async () => {
    setClearing(true);
    try {
      await api.clearAlerts();
      setDismissed(new Set(liveData.alerts.map(a => a.id)));
      addToast('All alerts cleared', 'success');
    } catch (e: any) {
      addToast(`Failed to clear: ${e.message}`, 'error');
    } finally {
      setClearing(false);
    }
  };

  const criticalCount  = alerts.filter(a => a.severity === 'critical').length;
  const highCount      = alerts.filter(a => a.severity === 'high').length;
  const unblockedCount = alerts.filter(a => !a.blocked).length;

  if (!liveData.connected && liveData.alerts.length === 0) {
    return (
      <div className="page-container">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, flexDirection: 'column', gap: 16, color: 'hsl(var(--text-secondary))' }}>
          <BellOff size={48} opacity={0.4} />
          <p style={{ fontSize: '0.9rem' }}>Backend offline — no notification data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container animate-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Bell size={20} style={{ color: 'hsl(var(--accent-color))' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Notifications Center</h2>
          {alerts.length > 0 && (
            <span style={{ background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444', borderRadius: 12, padding: '1px 8px', fontSize: '0.75rem', fontWeight: 700 }}>
              {alerts.length}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={() => liveData.refresh()} variant="secondary">
            <RefreshCw size={14} /> Refresh
          </Button>
          {alerts.length > 0 && (
            <Button onClick={clearAll} variant="danger" disabled={clearing}>
              <XCircle size={14} /> {clearing ? 'Clearing...' : 'Clear All'}
            </Button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Total Alerts',   value: alerts.length,   color: '#3b82f6', icon: <Bell size={16} /> },
          { label: 'Critical',       value: criticalCount,   color: '#ef4444', icon: <AlertTriangle size={16} /> },
          { label: 'High Severity',  value: highCount,       color: '#f97316', icon: <AlertTriangle size={16} /> },
          { label: 'Unblocked',      value: unblockedCount,  color: '#eab308', icon: <Info size={16} /> },
        ].map(({ label, value, color, icon }) => (
          <Card key={label}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ color, opacity: 0.8 }}>{icon}</div>
              <div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{label}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Filter bar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: '1rem', alignItems: 'center' }}>
        <Filter size={14} style={{ color: 'hsl(var(--text-secondary))' }} />
        {(['all', 'critical', 'high', 'unblocked'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '4px 14px', borderRadius: 6, fontSize: '0.78rem', fontWeight: 600,
              cursor: 'pointer', border: '1px solid',
              background:    filter === f ? 'hsl(var(--accent-color))' : 'transparent',
              color:         filter === f ? '#fff' : 'hsl(var(--text-secondary))',
              borderColor:   filter === f ? 'hsl(var(--accent-color))' : 'hsl(var(--border-primary))',
            }}
          >
            {f === 'all' ? 'All' : f === 'unblocked' ? 'Unblocked' : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {/* Alerts list */}
      {filtered.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 200, gap: 12, color: 'hsl(var(--text-secondary))' }}>
          <CheckCircle size={40} opacity={0.3} />
          <p style={{ fontSize: '0.9rem' }}>No notifications in this category</p>
        </div>
      ) : (
        <Card>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {filtered.map(alert => (
              <div
                key={alert.id}
                style={{
                  padding: '12px 14px',
                  borderRadius: 8,
                  background: 'hsl(var(--bg-secondary))',
                  border: '1px solid hsl(var(--border-primary))',
                  display: 'grid',
                  gridTemplateColumns: '1fr auto',
                  gap: 12,
                  alignItems: 'start',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <SeverityBadge s={alert.severity} />
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'hsl(var(--text-primary))' }}>
                      [{alert.engine}] {alert.type}
                    </span>
                    {alert.blocked && (
                      <span style={{ fontSize: '0.7rem', color: '#22c55e', fontWeight: 600 }}>(Blocked)</span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.77rem', color: 'hsl(var(--text-secondary))', display: 'flex', gap: 16 }}>
                    <span>{new Date(alert.timestamp).toLocaleString()}</span>
                    <span>{alert.src_ip}:{alert.src_port} — {alert.dst_ip}:{alert.dst_port}</span>
                    {alert.attck && <span style={{ color: '#8b5cf6' }}>{alert.attck}</span>}
                  </div>
                  {alert.payload && (
                    <div style={{ marginTop: 4, fontSize: '0.74rem', fontFamily: 'monospace', color: 'hsl(var(--text-secondary))', background: 'hsl(var(--bg-primary))', padding: '4px 8px', borderRadius: 4, wordBreak: 'break-all' }}>
                      {alert.payload.slice(0, 120)}{alert.payload.length > 120 ? '...' : ''}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => dismiss(alert.id)}
                  style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'hsl(var(--text-secondary))', padding: 4 }}
                  title="Dismiss"
                >
                  <XCircle size={16} />
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};
