import React, { useState } from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { api } from '../api/client';
import { Card } from '../components/UI/Card';
import { Table } from '../components/UI/Table';
import { Button } from '../components/UI/Button';
import { AlertTriangle, Shield, Filter, Globe, BarChart3 } from 'lucide-react';

interface RequestAnalysisProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
  setIncidents?: any;
}

const ATTACK_TYPES: Record<number, string> = {
  1: 'SQLi', 2: 'XSS', 3: 'RCE', 4: 'LFI', 5: 'Path Traversal',
  6: 'SSRF', 7: 'XXE', 8: 'SSTI', 9: 'ReDOS', 10: 'Log4Shell',
  11: 'Scanner', 12: 'Brute Force', 13: 'DDoS', 14: 'JWT',
  15: 'CORS', 16: 'Clickjacking', 17: 'Open Redirect', 18: 'CSP Bypass'
};

const getMethodBadge = (method: string) => {
  const colors: Record<string, string> = {
    GET: 'bg-blue-100 text-blue-800',
    POST: 'bg-green-100 text-green-800',
    PUT: 'bg-yellow-100 text-yellow-800',
    DELETE: 'bg-red-100 text-red-800',
  };
  return <span className={`px-2 py-1 rounded text-xs font-medium ${colors[method] || 'bg-gray-100 text-gray-800'}`}>{method}</span>;
};

const getScoreColor = (score: number) => {
  if (score > 70) return 'text-red-600 font-bold';
  if (score > 40) return 'text-yellow-600 font-bold';
  return 'text-gray-500';
};

export default function RequestAnalysis({ liveData, addToast }: RequestAnalysisProps) {
  const [expandedUriId, setExpandedUriId] = useState<number | null>(null);

  const handleProfileChange = async (profile: string) => {
    try {
      await api.wafSetProfile(profile);
      addToast(`WAF profile set to ${profile}`, 'success');
      liveData.refresh();
    } catch (e) {
      addToast('Failed to set WAF profile', 'error');
    }
  };

  const wg = liveData.stats?.webguard;
  const captures = liveData.wafCaptures || [];
  const rules = (liveData.wafRules || []).sort((a, b) => b.hit_count - a.hit_count).slice(0, 20);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
          <Shield className="w-6 h-6 text-indigo-600" /> WebGuard Analysis
        </h1>
        <div className="flex items-center gap-2 bg-white p-2 rounded-lg shadow-sm border border-gray-100">
          <span className="text-sm text-gray-500 mr-2 flex items-center gap-1"><Filter className="w-4 h-4"/> Profile:</span>
          {['Transparent', 'Moderate', 'Aggressive', 'Paranoid'].map(p => (
            <Button 
              key={p} 
              variant={wg?.profile === p ? 'primary' : 'secondary'} 
              size="sm"
              onClick={() => handleProfileChange(p)}
            >
              {p}
            </Button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        {[
          { label: 'SQL Injection', count: wg?.sqli_count || 0 },
          { label: 'XSS', count: wg?.xss_count || 0 },
          { label: 'RCE', count: wg?.rce_count || 0 },
          { label: 'LFI', count: wg?.lfi_count || 0 },
          { label: 'SSRF', count: wg?.ssrf_count || 0 },
          { label: 'Log4Shell', count: wg?.log4shell_count || 0 },
        ].map((stat, i) => (
          <Card key={i} className="p-4 flex flex-col items-center justify-center text-center">
            <AlertTriangle className="w-8 h-8 text-red-500 mb-2 opacity-80" />
            <div className="text-2xl font-bold text-gray-800">{stat.count.toLocaleString()}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">{stat.label}</div>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center gap-4">
          <Globe className="w-10 h-10 text-blue-500" />
          <div>
            <div className="text-sm text-gray-500">Inspected</div>
            <div className="text-xl font-bold">{wg?.requests_inspected?.toLocaleString() || 0}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4">
          <Shield className="w-10 h-10 text-green-500" />
          <div>
            <div className="text-sm text-gray-500">Blocked</div>
            <div className="text-xl font-bold">{wg?.requests_blocked?.toLocaleString() || 0}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4">
          <BarChart3 className="w-10 h-10 text-purple-500" />
          <div>
            <div className="text-sm text-gray-500">Rate Limit RPS</div>
            <div className="text-xl font-bold">{wg?.rate_limit_rps || 0}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4">
          <Filter className="w-10 h-10 text-orange-500" />
          <div>
            <div className="text-sm text-gray-500">IPs Banned</div>
            <div className="text-xl font-bold">{wg?.ips_banned?.toLocaleString() || 0}</div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card title="WAF Captures (Last 50)" className="overflow-hidden">
          <div className="overflow-auto max-h-[500px]">
            <table className="w-full text-sm text-left">
              <thead className="bg-gray-50 text-gray-600 sticky top-0">
                <tr>
                  <th className="px-4 py-2 font-medium">Time</th>
                  <th className="px-4 py-2 font-medium">Method</th>
                  <th className="px-4 py-2 font-medium">URI</th>
                  <th className="px-4 py-2 font-medium">Client IP</th>
                  <th className="px-4 py-2 font-medium">Score</th>
                  <th className="px-4 py-2 font-medium">Findings</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {captures.slice(0, 50).map(c => (
                  <tr key={c.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setExpandedUriId(expandedUriId === c.id ? null : c.id)}>
                    <td className="px-4 py-2 whitespace-nowrap">{new Date(c.timestamp).toLocaleTimeString()}</td>
                    <td className="px-4 py-2">{getMethodBadge(c.method)}</td>
                    <td className="px-4 py-2 max-w-xs">
                      <div className={expandedUriId === c.id ? 'break-all' : 'truncate'}>{c.uri}</div>
                    </td>
                    <td className="px-4 py-2 font-mono">{c.client_ip}</td>
                    <td className={`px-4 py-2 ${getScoreColor(c.score)}`}>{c.score}</td>
                    <td className="px-4 py-2">{c.finding_count}</td>
                    <td className="px-4 py-2">
                      {c.blocked ? 
                        <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs font-medium">Blocked</span> : 
                        <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs font-medium">Passed</span>}
                    </td>
                  </tr>
                ))}
                {captures.length === 0 && (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No recent captures</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Top Active Rules" className="overflow-hidden">
          <div className="overflow-auto max-h-[500px]">
            <table className="w-full text-sm text-left">
              <thead className="bg-gray-50 text-gray-600 sticky top-0">
                <tr>
                  <th className="px-4 py-2 font-medium">ID</th>
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="px-4 py-2 font-medium">Type</th>
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">ATT&CK</th>
                  <th className="px-4 py-2 font-medium text-right">Hits</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {rules.map(r => (
                  <tr key={r.rule_id} className="hover:bg-gray-50">
                    <td className="px-4 py-2 font-mono text-xs">{r.rule_id}</td>
                    <td className="px-4 py-2 font-medium truncate max-w-[200px]" title={r.name}>{r.name}</td>
                    <td className="px-4 py-2 text-gray-600">{ATTACK_TYPES[r.attack_type] || 'Unknown'}</td>
                    <td className="px-4 py-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${r.severity > 3 ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                        L{r.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs font-mono text-gray-500">{r.attck_technique}</td>
                    <td className="px-4 py-2 text-right font-bold">{r.hit_count.toLocaleString()}</td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No active rules</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
