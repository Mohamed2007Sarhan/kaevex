import React from 'react';
import { Card } from '../components/UI/Card';
import { Table } from '../components/UI/Table';
import { Users, Globe, Shield, Activity } from 'lucide-react';

export const Organizations: React.FC = () => {
  const users = [
    { name: 'Sarah Connor', email: 'sconnor@aegisshield.com', role: 'Security Analyst', status: 'Active', team: 'Blue Team (Triage)' },
    { name: 'John Connor', email: 'jconnor@aegisshield.com', role: 'Security Engineer', status: 'Active', team: 'Red Team (Response)' },
    { name: 'T-800', email: 'terminator@aegisshield.com', role: 'System Admin', status: 'Active', team: 'Operations' }
  ];

  const columns = [
    {
      header: 'Analyst Name',
      accessor: (u: typeof users[0]) => (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontWeight: 700 }}>{u.name}</span>
          <span style={{ fontSize: '0.675rem', color: 'hsl(var(--text-secondary))' }}>{u.email}</span>
        </div>
      )
    },
    { header: 'System Role', accessor: (u: typeof users[0]) => u.role },
    { header: 'Department Team', accessor: (u: typeof users[0]) => u.team },
    {
      header: 'Session Status',
      accessor: (u: typeof users[0]) => (
        <span className="badge badge-success">{u.status}</span>
      )
    }
  ];

  const roles = [
    { name: 'System Admin', desc: 'Full administrative access to all sensor integrations, settings, and agent parameters.', users: 1 },
    { name: 'Security Engineer', desc: 'Write firewall rules, toggle intrusion signatures, trigger host isolated workflows.', users: 1 },
    { name: 'Security Analyst', desc: 'Review alert events, log comment indicators, trigger sandboxed applications.', users: 1 }
  ];

  const roleColumns = [
    { header: 'Role Type', accessor: (r: typeof roles[0]) => <span style={{ fontWeight: 700, color: 'hsl(var(--accent-color))' }}>{r.name}</span> },
    { header: 'Access Policies & Capabilities', accessor: (r: typeof roles[0]) => <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{r.desc}</span> },
    { header: 'Assigned Analysts', accessor: (r: typeof roles[0]) => <strong>{r.users} users</strong> }
  ];

  return (
    <div className="page-container animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Organizations overview metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem' }}>
        <Card style={{ padding: '1rem' }} className="flex items-center gap-3">
          <Globe size={24} style={{ color: 'hsl(var(--accent-color))' }} />
          <div>
            <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase' }}>Organizations</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>1 Active Unit</div>
          </div>
        </Card>
        <Card style={{ padding: '1rem' }} className="flex items-center gap-3">
          <Users size={24} style={{ color: 'hsl(var(--color-success))' }} />
          <div>
            <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase' }}>Operating Teams</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>3 Security Teams</div>
          </div>
        </Card>
        <Card style={{ padding: '1rem' }} className="flex items-center gap-3">
          <Shield size={24} style={{ color: 'hsl(var(--color-medium))' }} />
          <div>
            <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase' }}>Active Sessions</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>3 Analysts Online</div>
          </div>
        </Card>
      </div>

      {/* Users and Roles tabs */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
        <div>
          <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Security Administrators & Analysts</h3>
          <Table columns={columns} data={users} />
        </div>
        <div>
          <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>Access Control Roles Policies</h3>
          <Table columns={roleColumns} data={roles} />
        </div>
      </div>
    </div>
  );
};
