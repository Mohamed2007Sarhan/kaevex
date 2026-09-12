import React, { useState } from 'react';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { Table } from '../components/UI/Table';
import { AreaChart, BarChart } from '../components/UI/Charts';
import { Bot, Shield, Terminal, Key, Cpu, Sliders, MessageSquare, Clock } from 'lucide-react';

interface AIAgent {
  id: string;
  name: string;
  role: string;
  status: 'Idle' | 'Active' | 'Thinking' | 'Error';
  health: 'Healthy' | 'Degraded';
  permissions: string[];
  activity: string;
  reasoning: string[];
  cpu: number;
  memory: number;
  lastActive: string;
}

interface AIWorkspaceProps {
  addToast: (msg: string, severity: 'success' | 'info' | 'warning' | 'error') => void;
}

export const AIWorkspace: React.FC<AIWorkspaceProps> = ({ addToast }) => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'roster' | 'prompts' | 'logs'>('dashboard');
  
  // Expanded Agent database
  const [agents, setAgents] = useState<AIAgent[]>([
    {
      id: 'ag-1',
      name: 'Triage Agent',
      role: 'L1 Log Enrichment & Correlation',
      status: 'Thinking',
      health: 'Healthy',
      permissions: ['Read logs', 'Query threat DB', 'Trigger warning logs'],
      activity: 'Analyzing Suricata event logs for SSH Brute Force attempts.',
      reasoning: [
        'Ingested 1,245 log lines from suricata.log',
        'Detected 14 consecutive SSH authentication failures from external IP 198.51.100.42 to app-web-01',
        'Cross-referenced 198.51.100.42 against Threat Intelligence feeds; matched AlienVault malicious registry with 98% threat score',
        'Determined high-confidence brute-force attack in progress',
        'Generating alert incident and notifying Response Agent.'
      ],
      cpu: 45,
      memory: 58,
      lastActive: 'Just Now'
    },
    {
      id: 'ag-2',
      name: 'Forensic Agent',
      role: 'Deep Host & Memory Analytics',
      status: 'Idle',
      health: 'Healthy',
      permissions: ['Read filesystem', 'Process inspection', 'Memory analysis'],
      activity: 'Idle. Monitoring host state for integrity changes.',
      reasoning: [
        'Completed file integrity integrity scan on /usr/sbin/nginx',
        'Identified binary modifications matching unknown checksums',
        'Extracted active processes; no rogue daemon running from nginx PID namespace',
        'Marked vulnerability CVE-2024-3094 as a potential prerequisite',
        'Submitted full file report to Sandbox Analysis'
      ],
      cpu: 5,
      memory: 22,
      lastActive: '5m ago'
    },
    {
      id: 'ag-3',
      name: 'Response Agent',
      role: 'Automated Threat Mitigation',
      status: 'Active',
      health: 'Healthy',
      permissions: ['Write firewalls', 'Kill processes', 'Isolate endpoints'],
      activity: 'Deploying IP block on boundary firewall rules.',
      reasoning: [
        'Received brute-force alert from Triage Agent',
        'Verified active session state for source 198.51.100.42',
        'Evaluated compliance impact of host isolation; app-web-01 is public facing frontend, host isolation denied',
        'Formulating network level mitigation plan',
        'Executing firewalld block rule for IP 198.51.100.42 on app-web-01 boundary card'
      ],
      cpu: 18,
      memory: 34,
      lastActive: '1m ago'
    }
  ]);

  const [selectedAgent, setSelectedAgent] = useState<AIAgent>(agents[0]);
  const [editingPrompt, setEditingPrompt] = useState(false);
  const [promptText, setPromptText] = useState(
    `You are the Aegis Triage Agent. Your instructions are to ingest all incoming NIDS logs, correlate multiple connection failures or security alerts, query threat intelligence reputation databases, and coordinate responses with the Response Agent.`
  );

  // Execution Policies Mock
  const [policies, setPolicies] = useState([
    { id: 'p-1', name: 'Auto-Containment Firewalls', desc: 'Deploy automated firewall blocks upon high-confidence malicious host triggers.', enabled: true },
    { id: 'p-2', name: 'Endpoint Host Isolation', desc: 'Isolate compromised workstations from local subnets automatically.', enabled: false },
    { id: 'p-3', name: 'MFA Verification Gates', desc: 'Request analyst confirmation triggers before initiating host system rollbacks.', enabled: true }
  ]);

  const togglePolicy = (id: string, name: string) => {
    setPolicies(prev =>
      prev.map(p => {
        if (p.id === id) {
          const nextVal = !p.enabled;
          addToast(`AI Execution Policy "${name}" successfully ${nextVal ? 'enabled' : 'disabled'}.`, 'info');
          return { ...p, enabled: nextVal };
        }
        return p;
      })
    );
  };

  const savePrompt = () => {
    setEditingPrompt(false);
    addToast(`${selectedAgent.name} instruction prompt saved successfully.`, 'success');
  };

  // Decisions list mock
  const decisions = [
    { time: '05:40:12', agent: 'Response Agent', action: 'Applied IPTables Firewall Block [IP: 198.51.100.42]', trigger: 'Correlation match SSH brute force', result: 'Completed' },
    { time: '05:38:00', agent: 'Triage Agent', action: 'Created Security Incident ticket INC-2026-804', trigger: 'SQL Injection payload matched on frontend', result: 'Completed' }
  ];

  const decisionColumns = [
    { header: 'Time', accessor: (d: typeof decisions[0]) => d.time },
    { header: 'Agent Actor', accessor: (d: typeof decisions[0]) => <span style={{ fontWeight: 700 }}>{d.agent}</span> },
    { header: 'Action Executed', accessor: (d: typeof decisions[0]) => d.action },
    { header: 'Trigger Cause', accessor: (d: typeof decisions[0]) => d.trigger },
    {
      header: 'Result',
      accessor: (d: typeof decisions[0]) => (
        <span className="badge badge-success">{d.result}</span>
      )
    }
  ];

  const tokenUsageData = [
    { label: '05:00', value: 8400 },
    { label: '05:05', value: 12000 },
    { label: '05:10', value: 9200 },
    { label: '05:15', value: 15400 },
    { label: '05:20', value: 11000 }
  ];

  return (
    <div className="page-container animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Sub tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid hsl(var(--border-primary))', gap: '1.5rem' }}>
        {['Dashboard', 'Agent Roster', 'Prompt Manager', 'Decision Logs'].map((tab, idx) => {
          const tabId = ['dashboard', 'roster', 'prompts', 'logs'][idx];
          return (
            <button
              key={tabId}
              onClick={() => setActiveTab(tabId as any)}
              style={{
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === tabId ? '2px solid hsl(var(--accent-color))' : '2px solid transparent',
                color: activeTab === tabId ? 'hsl(var(--text-primary))' : 'hsl(var(--text-secondary))',
                paddingBottom: '0.5rem',
                fontWeight: 600,
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              {tab}
            </button>
          );
        })}
      </div>

      {activeTab === 'dashboard' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Stats metrics */}
          <div className="metrics-grid">
            <Card style={{ padding: '1rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))' }}>TOTAL AGENTS ONLINE</div>
              <div className="card-value" style={{ color: 'hsl(var(--color-success))', marginTop: '0.25rem' }}>3 / 3</div>
            </Card>
            <Card style={{ padding: '1rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))' }}>DECISIONS COMPLETED</div>
              <div className="card-value" style={{ marginTop: '0.25rem' }}>148 runs</div>
            </Card>
            <Card style={{ padding: '1rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))' }}>REASONING LATENCY</div>
              <div className="card-value" style={{ color: 'hsl(var(--accent-color))', marginTop: '0.25rem' }}>42 ms</div>
            </Card>
          </div>

          <div className="charts-grid">
            <Card>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '1rem' }}>LLM Tokens Consumption (5m range)</h3>
              <AreaChart data={tokenUsageData} height={160} color="hsl(var(--accent-color))" />
            </Card>

            <Card style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>AI Recommendations summary</h3>
              <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.5 }}>
                Aegis AI suggests upgrading Adobe Acrobat PDF Reader across employee workstation endpoints to patch CVE-2023-4863 vulnerabilities. 
                Auto-mitigation policies blocks outgoing flows from known malicious ranges instantly.
              </p>
            </Card>
          </div>
        </div>
      ) : activeTab === 'roster' ? (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }} className="animate-fade-in">
          
          {/* Agent grid cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {agents.map((agent) => (
              <Card
                key={agent.id}
                onClick={() => setSelectedAgent(agent)}
                style={{
                  cursor: 'pointer',
                  border: selectedAgent.id === agent.id ? '2px solid hsl(var(--accent-color))' : '1px solid hsl(var(--border-primary))'
                }}
                className="flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <div style={{ backgroundColor: 'hsl(var(--accent-light))', color: 'hsl(var(--accent-color))', padding: '8px', borderRadius: '50%', display: 'flex' }}>
                    <Bot size={20} />
                  </div>
                  <div>
                    <h4 style={{ fontSize: '0.85rem', fontWeight: 700 }}>{agent.name}</h4>
                    <div style={{ fontSize: '0.675rem', color: 'hsl(var(--text-secondary))' }}>{agent.role}</div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.75rem', textAlign: 'right' }}>
                  <div>
                    <div style={{ fontSize: '0.6rem', color: 'hsl(var(--text-secondary))' }}>CPU / RAM</div>
                    <div style={{ fontWeight: 700 }}>{agent.cpu}% / {agent.memory}%</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.6rem', color: 'hsl(var(--text-secondary))' }}>STATUS</div>
                    <span className={`badge ${agent.status === 'Thinking' ? 'badge-medium' : 'badge-success'}`}>{agent.status}</span>
                  </div>
                </div>
              </Card>
            ))}
          </div>

          {/* Selected Agent Details */}
          <Card style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem', height: 'fit-content' }}>
            <div style={{ borderBottom: '1px solid hsl(var(--border-primary))', paddingBottom: '0.5rem' }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>{selectedAgent.name} Reasoning</h3>
              <span style={{ fontSize: '0.65rem', color: 'hsl(var(--text-secondary))' }}>Active: {selectedAgent.activity}</span>
            </div>

            <div>
              <div className="flex items-center gap-1" style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                <Cpu size={12} />
                <span>Reasoning Steps Logs</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {selectedAgent.reasoning.map((step, idx) => (
                  <div key={idx} style={{ padding: '0.5rem', backgroundColor: 'hsl(var(--bg-tertiary))', border: '1px solid hsl(var(--border-primary))', borderRadius: '4px', fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}>
                    {step}
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="flex items-center gap-1" style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                <Key size={12} />
                <span>Assigned permissions</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                {selectedAgent.permissions.map((p, i) => (
                  <span key={i} className="badge badge-info" style={{ fontSize: '0.65rem' }}>{p}</span>
                ))}
              </div>
            </div>
          </Card>

        </div>
      ) : activeTab === 'prompts' ? (
        <div className="animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
          {/* Prompt management */}
          <Card style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <MessageSquare size={16} style={{ color: 'hsl(var(--accent-color))' }} />
                <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>System instructions Prompt ({selectedAgent.name})</h3>
              </div>
              <Button size="sm" onClick={() => editingPrompt ? savePrompt() : setEditingPrompt(true)}>
                {editingPrompt ? 'Save instruction' : 'Edit instruction'}
              </Button>
            </div>
            
            {editingPrompt ? (
              <textarea
                className="input-field"
                style={{ flex: 1, resize: 'none', minHeight: '140px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
                value={promptText}
                onChange={e => setPromptText(e.target.value)}
              />
            ) : (
              <p style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.6, flex: 1 }}>
                {promptText}
              </p>
            )}
          </Card>

          {/* Execution Policies */}
          <Card style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div className="flex items-center gap-2">
              <Sliders size={16} style={{ color: 'hsl(var(--color-medium))' }} />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>AI Execution Guardrails</h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {policies.map((p) => (
                <div key={p.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.75rem', borderBottom: '1px solid hsl(var(--border-primary))' }}>
                  <div style={{ flex: 1, marginRight: '1.5rem' }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>{p.name}</div>
                    <div style={{ fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', marginTop: '0.15rem' }}>{p.desc}</div>
                  </div>
                  <button
                    onClick={() => togglePolicy(p.id, p.name)}
                    style={{
                      background: 'transparent',
                      cursor: 'pointer',
                      color: p.enabled ? 'hsl(var(--color-success))' : 'hsl(var(--text-secondary))',
                      display: 'flex',
                      alignItems: 'center'
                    }}
                  >
                    {p.enabled ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
                  </button>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ) : (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>AI Autonomous Decisions History</h3>
          <Table columns={decisionColumns} data={decisions} />
        </div>
      )}
    </div>
  );
};

// Help Toggles
const ToggleRight = ({ size, color = 'hsl(var(--color-success))' }: { size: number; color?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ cursor: 'pointer' }}>
    <rect width="20" height="12" x="2" y="6" rx="6" fill={color} fillOpacity="0.2" />
    <circle cx="16" cy="12" r="4" fill={color} />
  </svg>
);

const ToggleLeft = ({ size, color = 'hsl(var(--text-secondary))' }: { size: number; color?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ cursor: 'pointer' }}>
    <rect width="20" height="12" x="2" y="6" rx="6" fill="transparent" />
    <circle cx="8" cy="12" r="4" fill={color} />
  </svg>
);
