/**
 * AegisCore — AuditLogs Page
 * Shows local action log for operator actions.
 * No mock data. No emoji.
 */
import React, { useState } from 'react';
import { ClipboardList, Search, Download, CheckCircle, XCircle } from 'lucide-react';
import { Card } from '../components/UI/Card';

interface AuditEntry {
  id: string;
  time: string;
  user: string;
  action: string;
  module: string;
  ip: string;
  status: 'Success' | 'Failed';
}

interface AuditLogsProps {
  logs: AuditEntry[];
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ logs }) => {
  const [search, setSearch] = useState('');

  const filtered = logs.filter(l =>
    !search ||
    l.action.toLowerCase().includes(search.toLowerCase()) ||
    l.module.toLowerCase().includes(search.toLowerCase()) ||
    l.user.toLowerCase().includes(search.toLowerCase()) ||
    l.ip.includes(search)
  );

  const exportCSV = () => {
    const rows = ['Time,User,Action,Module,IP,Status', ...logs.map(l =>
      `"${l.time}","${l.user}","${l.action.replace(/"/g, '\\"')}","${l.module}","${l.ip}","${l.status}"`
    )].join('\n');
    const blob = new Blob([rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `aegiscore-audit-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page-container animate-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ClipboardList size={20} style={{ color: 'hsl(var(--accent-color))' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Audit Logs</h2>
          <span style={{ fontSize: '0.78rem', color: 'hsl(var(--text-secondary))' }}>{logs.length} entries</span>
        </div>
        <button
          onClick={exportCSV}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 14px', borderRadius: 8,
            background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-primary))',
            color: 'hsl(var(--text-primary))', cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
          }}
        >
          <Download size={14} /> Export CSV
        </button>
      </div>

      {/* Search */}
      <div style={{ position: 'relative', marginBottom: '1rem', maxWidth: 360 }}>
        <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'hsl(var(--text-secondary))' }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search logs..."
          style={{
            width: '100%', padding: '7px 10px 7px 32px',
            background: 'hsl(var(--bg-secondary))', border: '1px solid hsl(var(--border-primary))',
            borderRadius: 8, color: 'hsl(var(--text-primary))', fontSize: '0.82rem',
          }}
        />
      </div>

      {/* Table */}
      <Card>
        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'hsl(var(--text-secondary))' }}>
            <ClipboardList size={32} opacity={0.3} style={{ display: 'block', margin: '0 auto 8px' }} />
            <p style={{ fontSize: '0.88rem' }}>No log entries yet. Actions taken in the dashboard will appear here.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.81rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid hsl(var(--border-primary))' }}>
                  {['Time', 'User', 'Action', 'Module', 'IP', 'Status'].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'hsl(var(--text-secondary))', fontSize: '0.72rem', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((l, i) => (
                  <tr key={l.id} style={{ borderBottom: '1px solid hsl(var(--border-primary))', background: i % 2 === 0 ? 'transparent' : 'hsl(var(--bg-secondary) / 0.4)' }}>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: '0.77rem', color: 'hsl(var(--text-secondary))' }}>{l.time}</td>
                    <td style={{ padding: '8px 12px', fontWeight: 600 }}>{l.user}</td>
                    <td style={{ padding: '8px 12px' }}>{l.action}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{ padding: '2px 7px', borderRadius: 4, background: 'hsl(var(--accent-color) / 0.1)', color: 'hsl(var(--accent-color))', fontSize: '0.72rem', fontWeight: 600 }}>
                        {l.module}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: '0.77rem' }}>{l.ip}</td>
                    <td style={{ padding: '8px 12px' }}>
                      {l.status === 'Success' ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22c55e', fontSize: '0.77rem', fontWeight: 600 }}>
                          <CheckCircle size={12} /> Success
                        </span>
                      ) : (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#ef4444', fontSize: '0.77rem', fontWeight: 600 }}>
                          <XCircle size={12} /> Failed
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};
