/**
 * AegisCore — Assets Page
 * Shows software components and system inventory from HostGuard.
 * No mock data. No emoji.
 */
import React, { useState } from 'react';
import { Server, Search, Package, RefreshCw, AlertCircle, CheckCircle, Cpu } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Table } from '../components/UI/Table';
import { Button } from '../components/UI/Button';
import { AegisLiveData } from '../api/useAegisData';
import { api } from '../api/client';

interface AssetsProps {
  liveData: AegisLiveData;
  assets?: any;
}

function formatDate(s: string) {
  try { return new Date(s).toLocaleDateString(); } catch { return s; }
}

export const Assets: React.FC<AssetsProps> = ({ liveData }) => {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const components = liveData.hgComponents ?? [];

  const types = Array.from(new Set(components.map(c => c.type).filter(Boolean)));

  const filtered = components.filter(c => {
    const matchSearch = !search ||
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.version.toLowerCase().includes(search.toLowerCase());
    const matchType = typeFilter === 'all' || c.type === typeFilter;
    return matchSearch && matchType;
  });

  const needsCVE   = components.filter(c => c.needs_cve_check).length;
  const needsUpd   = components.filter(c => (c as any).needs_update_check).length;

  const runScan = async () => {
    try {
      await api.hostguardForceScan();
    } catch (e: any) { /* ignore — fire and forget */ }
  };

  if (liveData.loading && components.length === 0) {
    return (
      <div className="page-container">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[...Array(6)].map((_, i) => (
            <div key={i} style={{ height: 48, borderRadius: 8, background: 'hsl(var(--bg-secondary))', animation: 'pulse 1.5s infinite' }} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="page-container animate-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Server size={20} style={{ color: 'hsl(var(--accent-color))' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Software Inventory</h2>
          <span style={{ fontSize: '0.78rem', color: 'hsl(var(--text-secondary))' }}>
            {components.length} components tracked by HostGuard
          </span>
        </div>
        <Button onClick={runScan} variant="secondary">
          <RefreshCw size={14} /> Trigger Rescan
        </Button>
      </div>

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Total Components', value: components.length,                        icon: <Package size={16} />,       color: '#3b82f6' },
          { label: 'CVE Check Needed', value: needsCVE,                                 icon: <AlertCircle size={16} />,   color: needsCVE > 0 ? '#ef4444' : '#22c55e' },
          { label: 'Updates Available',value: needsUpd,                                 icon: <RefreshCw size={16} />,     color: needsUpd > 0 ? '#f97316' : '#22c55e' },
          { label: 'Auto-Scanned',     value: liveData.stats?.hostguard.stat_components_scanned ?? 0, icon: <Cpu size={16} />, color: '#8b5cf6' },
        ].map(({ label, value, icon, color }) => (
          <Card key={label}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ color }}>{icon}</div>
              <div>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: '0.72rem', color: 'hsl(var(--text-secondary))' }}>{label}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: '1rem', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 320 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'hsl(var(--text-secondary))' }} />
          <input
            placeholder="Search by name or version..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%', padding: '7px 10px 7px 32px',
              background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-primary))',
              borderRadius: 8, color: 'hsl(var(--text-primary))', fontSize: '0.82rem',
            }}
          />
        </div>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{
            padding: '7px 12px', background: 'hsl(var(--bg-secondary))',
            border: '1px solid hsl(var(--border-primary))', borderRadius: 8,
            color: 'hsl(var(--text-primary))', fontSize: '0.82rem',
          }}
        >
          <option value="all">All Types</option>
          {types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: 200, justifyContent: 'center', gap: 12, color: 'hsl(var(--text-secondary))' }}>
          <Package size={40} opacity={0.3} />
          <p style={{ fontSize: '0.9rem' }}>{components.length === 0 ? 'No components discovered yet. Run a scan to populate inventory.' : 'No components match your search.'}</p>
        </div>
      ) : (
        <Card>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid hsl(var(--border-primary))' }}>
                  {['Name', 'Version', 'Type', 'OS', 'Last Seen', 'CVE Check', 'Update Check'].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'hsl(var(--text-secondary))', fontSize: '0.73rem', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 100).map((c, i) => (
                  <tr
                    key={c.db_id}
                    style={{
                      borderBottom: '1px solid hsl(var(--border-primary))',
                      background: i % 2 === 0 ? 'transparent' : 'hsl(var(--bg-secondary) / 0.4)',
                    }}
                  >
                    <td style={{ padding: '8px 12px', fontWeight: 600, color: 'hsl(var(--text-primary))' }}>{c.name}</td>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: '0.78rem' }}>{c.version || '—'}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{ padding: '2px 8px', borderRadius: 4, background: 'hsl(var(--accent-color) / 0.1)', color: 'hsl(var(--accent-color))', fontSize: '0.72rem', fontWeight: 600 }}>
                        {c.type || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', color: 'hsl(var(--text-secondary))', fontSize: '0.78rem' }}>{c.os_info || '—'}</td>
                    <td style={{ padding: '8px 12px', color: 'hsl(var(--text-secondary))' }}>{formatDate(c.last_seen)}</td>
                    <td style={{ padding: '8px 12px' }}>
                      {c.needs_cve_check ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#ef4444', fontSize: '0.75rem', fontWeight: 600 }}>
                          <AlertCircle size={12} /> Yes
                        </span>
                      ) : (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22c55e', fontSize: '0.75rem' }}>
                          <CheckCircle size={12} /> No
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      {(c as any).needs_update_check ? (
                        <span style={{ color: '#f97316', fontSize: '0.75rem', fontWeight: 600 }}>Pending</span>
                      ) : (
                        <span style={{ color: '#22c55e', fontSize: '0.75rem' }}>OK</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length > 100 && (
              <p style={{ textAlign: 'center', color: 'hsl(var(--text-secondary))', fontSize: '0.78rem', padding: '8px' }}>
                Showing 100 of {filtered.length} results. Refine your search to see more.
              </p>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};
