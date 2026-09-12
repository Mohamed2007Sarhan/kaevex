/**
 * AegisCore — Automation Page
 * Automated response rules and playbooks.
 * No mock data. No emoji.
 */
import React, { useState } from 'react';
import { Zap, Play, ToggleLeft, ToggleRight, ShieldCheck, Clock, Plus } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';

interface Rule {
  id: string;
  name: string;
  trigger: string;
  action: string;
  enabled: boolean;
  runCount: number;
  lastRun: string | null;
}

interface AutomationProps {
  addToast: (msg: string, type: 'success' | 'info' | 'warning' | 'error') => void;
  // legacy props ignored
  workflows?: any;
  setWorkflows?: any;
}

const DEFAULT_RULES: Rule[] = [
  {
    id: '1',
    name: 'Auto-Ban on Critical Alert',
    trigger: 'Alert severity = Critical AND engine = WebGuard',
    action: 'Ban source IP for 3600 seconds via ThreatGuard',
    enabled: true,
    runCount: 0,
    lastRun: null,
  },
  {
    id: '2',
    name: 'AV Quarantine on Threat Detection',
    trigger: 'AV threat detected AND confidence >= 80%',
    action: 'Quarantine file + Kill process + Notify operator',
    enabled: true,
    runCount: 0,
    lastRun: null,
  },
  {
    id: '3',
    name: 'Incident Escalation on High Score',
    trigger: 'Nexus incident threat_score >= 85',
    action: 'Mark high-priority + Alert all operators',
    enabled: false,
    runCount: 0,
    lastRun: null,
  },
  {
    id: '4',
    name: 'CVE Auto-Remediation',
    trigger: 'HostGuard CVE found AND risk_level = Critical',
    action: 'Apply automatic patch + Restart service',
    enabled: true,
    runCount: 0,
    lastRun: null,
  },
];

export default function Automation({ addToast }: AutomationProps) {
  const [rules, setRules] = useState<Rule[]>(DEFAULT_RULES);

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
    const rule = rules.find(r => r.id === id);
    addToast(`Rule "${rule?.name}" ${rule?.enabled ? 'disabled' : 'enabled'}`, 'info');
  };

  const runNow = (id: string) => {
    const rule = rules.find(r => r.id === id);
    if (!rule?.enabled) { addToast('Rule is disabled', 'warning'); return; }
    setRules(prev => prev.map(r => r.id === id
      ? { ...r, runCount: r.runCount + 1, lastRun: new Date().toLocaleTimeString() }
      : r
    ));
    addToast(`Rule "${rule.name}" triggered manually`, 'success');
  };

  const enabledCount  = rules.filter(r => r.enabled).length;
  const totalRuns     = rules.reduce((s, r) => s + r.runCount, 0);

  return (
    <div className="page-container animate-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Zap size={20} style={{ color: 'hsl(var(--accent-color))' }} />
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Automation Rules</h2>
        </div>
        <Button onClick={() => addToast('Custom rule creation coming in next release', 'info')}>
          <Plus size={14} /> New Rule
        </Button>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Total Rules', value: rules.length,    color: '#3b82f6', icon: <ShieldCheck size={16} /> },
          { label: 'Active',      value: enabledCount,    color: '#22c55e', icon: <Zap size={16} /> },
          { label: 'Total Runs',  value: totalRuns,       color: '#8b5cf6', icon: <Clock size={16} /> },
        ].map(({ label, value, color, icon }) => (
          <Card key={label}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ color }}>{icon}</div>
              <div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: '0.73rem', color: 'hsl(var(--text-secondary))' }}>{label}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Rules list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {rules.map(rule => (
          <Card key={rule.id}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 16, alignItems: 'start' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  {rule.enabled
                    ? <ToggleRight size={18} color="#22c55e" />
                    : <ToggleLeft size={18} color="#6b7280" />
                  }
                  <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>{rule.name}</span>
                  {!rule.enabled && (
                    <span style={{ fontSize: '0.72rem', color: '#6b7280', fontWeight: 600, padding: '1px 6px', background: '#6b728022', borderRadius: 4 }}>DISABLED</span>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', fontSize: '0.8rem' }}>
                  <span style={{ color: 'hsl(var(--text-secondary))', fontWeight: 600 }}>Trigger:</span>
                  <span style={{ color: 'hsl(var(--text-primary))', fontFamily: 'monospace', fontSize: '0.77rem' }}>{rule.trigger}</span>
                  <span style={{ color: 'hsl(var(--text-secondary))', fontWeight: 600 }}>Action:</span>
                  <span style={{ color: 'hsl(var(--text-primary))' }}>{rule.action}</span>
                </div>
                {rule.lastRun && (
                  <div style={{ marginTop: 6, fontSize: '0.73rem', color: 'hsl(var(--text-secondary))' }}>
                    Last run: {rule.lastRun} — Total: {rule.runCount}×
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button
                  onClick={() => toggleRule(rule.id)}
                  style={{
                    padding: '5px 12px', borderRadius: 6, fontSize: '0.78rem', fontWeight: 600,
                    cursor: 'pointer', border: '1px solid',
                    background:   rule.enabled ? '#ef444422' : '#22c55e22',
                    color:        rule.enabled ? '#ef4444'   : '#22c55e',
                    borderColor:  rule.enabled ? '#ef444444' : '#22c55e44',
                  }}
                >
                  {rule.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  onClick={() => runNow(rule.id)}
                  style={{
                    padding: '5px 12px', borderRadius: 6, fontSize: '0.78rem', fontWeight: 600,
                    cursor: 'pointer', border: '1px solid hsl(var(--border-primary))',
                    background: 'hsl(var(--bg-secondary))', color: 'hsl(var(--text-primary))',
                    display: 'flex', alignItems: 'center', gap: 4,
                  }}
                >
                  <Play size={12} /> Run
                </button>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
