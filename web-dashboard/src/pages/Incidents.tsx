import React, { useState } from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { Card } from '../components/UI/Card';
import { Flame, Target, Activity, Shield, ChevronDown, ChevronUp } from 'lucide-react';

interface IncidentsProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
  incidents?: any;
  setIncidents?: any;
}

const KILL_CHAIN_STAGES: Record<number, string> = {
  1: 'Recon', 2: 'Weaponize', 3: 'Deliver', 4: 'Exploit', 5: 'Install', 6: 'C2', 7: 'Exfil'
};

const getScoreColor = (score: number) => {
  if (score >= 80) return 'bg-red-500';
  if (score >= 60) return 'bg-orange-500';
  if (score >= 40) return 'bg-yellow-500';
  return 'bg-blue-500';
};

export default function Incidents({ liveData }: IncidentsProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  
  const incidents = liveData.incidents || [];
  const sessions = liveData.sessions || [];
  const nex = liveData.stats?.nexus;

  const totalIncidents = nex?.incidents_created || incidents.length;
  const critIncidents = incidents.filter(i => i.threat_score >= 80).length;
  const autoRemediated = incidents.filter(i => i.auto_remediated).length;
  const activeSessions = nex?.active_sessions || sessions.length;

  const killChainCounts = [1,2,3,4,5,6,7].map(stage => sessions.filter(s => s.kill_chain_stage === stage).length);
  const maxChainCount = Math.max(...killChainCounts, 1);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
          <Flame className="w-6 h-6 text-red-600" /> Nexus Incidents & Sessions
        </h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center gap-4 border-l-4 border-blue-500">
          <Activity className="w-10 h-10 text-blue-500 opacity-80" />
          <div>
            <div className="text-sm text-gray-500 font-medium">Total Incidents</div>
            <div className="text-2xl font-bold">{totalIncidents}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4 border-l-4 border-red-500">
          <Flame className="w-10 h-10 text-red-500 opacity-80" />
          <div>
            <div className="text-sm text-gray-500 font-medium">Critical Incidents</div>
            <div className="text-2xl font-bold">{critIncidents}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4 border-l-4 border-green-500">
          <Shield className="w-10 h-10 text-green-500 opacity-80" />
          <div>
            <div className="text-sm text-gray-500 font-medium">Auto-Remediated</div>
            <div className="text-2xl font-bold">{autoRemediated}</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center gap-4 border-l-4 border-purple-500">
          <Target className="w-10 h-10 text-purple-500 opacity-80" />
          <div>
            <div className="text-sm text-gray-500 font-medium">Active Sessions</div>
            <div className="text-2xl font-bold">{activeSessions}</div>
          </div>
        </Card>
      </div>

      <Card title="Security Incidents" className="overflow-hidden">
        <div className="overflow-auto max-h-[600px]">
          <table className="w-full text-sm text-left">
            <thead className="bg-gray-50 text-gray-600 sticky top-0 z-10">
              <tr>
                <th className="w-10"></th>
                <th className="px-4 py-3 font-medium">ID</th>
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Attacker &rarr; Target</th>
                <th className="px-4 py-3 font-medium">Kill Chain</th>
                <th className="px-4 py-3 font-medium">Threat Score</th>
                <th className="px-4 py-3 font-medium">Family</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {incidents.map(inc => (
                <React.Fragment key={inc.incident_id}>
                  <tr className="hover:bg-gray-50 cursor-pointer" onClick={() => setExpandedId(expandedId === inc.incident_id ? null : inc.incident_id)}>
                    <td className="px-4 py-3 text-gray-400">
                      {expandedId === inc.incident_id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{String(inc.incident_id)}</td>
                    <td className="px-4 py-3 font-medium text-gray-800">{inc.title}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className="font-mono text-red-600">{inc.attacker_ip}</span> &rarr; <span className="font-mono text-blue-600">{inc.target_ip}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="bg-gray-100 text-gray-700 px-2 py-1 rounded text-xs font-medium">
                        {KILL_CHAIN_STAGES[inc.kill_chain_stage] || `Stage ${inc.kill_chain_stage}`}
                      </span>
                    </td>
                    <td className="px-4 py-3 min-w-[120px]">
                      <div className="flex items-center gap-2">
                        <span className="font-bold w-6">{inc.threat_score}</span>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div className={`h-2 rounded-full ${getScoreColor(inc.threat_score)}`} style={{ width: `${inc.threat_score}%` }}></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-600">{inc.threat_family || '-'}</td>
                    <td className="px-4 py-3">
                      {inc.auto_remediated ? 
                        <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs font-medium">Remediated</span> : 
                        <span className="bg-orange-100 text-orange-800 px-2 py-1 rounded text-xs font-medium">Open</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{new Date(inc.created).toLocaleString()}</td>
                  </tr>
                  {expandedId === inc.incident_id && (
                    <tr className="bg-gray-50 border-b border-gray-200">
                      <td colSpan={9} className="px-8 py-4">
                        <div className="grid grid-cols-2 gap-6">
                          <div>
                            <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Summary</h4>
                            <p className="text-sm text-gray-800 mb-4">{inc.summary}</p>
                            <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Techniques</h4>
                            <div className="flex flex-wrap gap-2">
                              {String(inc.techniques ?? '').split(',').filter(Boolean).map((t: string, i: number) => (
                                <span key={i} className="bg-indigo-100 text-indigo-800 px-2 py-1 rounded text-xs font-mono">{t}</span>
                              ))}
                            </div>
                          </div>
                          <div>
                            <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Remediation Action</h4>
                            <p className="text-sm text-gray-800">{inc.remediation || 'No action taken automatically.'}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
              {incidents.length === 0 && (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-gray-500">No incidents to display</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Card title="Active Attack Sessions" className="xl:col-span-2 overflow-hidden">
          <div className="overflow-auto max-h-[400px]">
            <table className="w-full text-sm text-left">
              <thead className="bg-gray-50 text-gray-600 sticky top-0">
                <tr>
                  <th className="px-4 py-2 font-medium">Attacker &rarr; Target</th>
                  <th className="px-4 py-2 font-medium">Kill Chain</th>
                  <th className="px-4 py-2 font-medium">Score</th>
                  <th className="px-4 py-2 font-medium">Level</th>
                  <th className="px-4 py-2 font-medium">Responses</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {sessions.map(s => (
                  <tr key={s.session_id} className="hover:bg-gray-50">
                    <td className="px-4 py-2 text-xs">
                      <span className="font-mono">{s.attacker_ip}</span><br/><span className="text-gray-400">&darr;</span><br/><span className="font-mono text-gray-600">{s.target_ip}</span>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {KILL_CHAIN_STAGES[s.kill_chain_stage] || s.kill_chain_stage}
                      <div className="text-gray-400 mt-1">{s.event_count} events</div>
                    </td>
                    <td className="px-4 py-2 font-bold">{s.correlated_score}</td>
                    <td className="px-4 py-2 text-xs">{String(s.threat_level)}</td>
                    <td className="px-4 py-2">
                      <div className="flex flex-wrap gap-1">
                        {s.ip_banned && <span className="bg-red-100 text-red-800 px-1.5 py-0.5 rounded text-[10px] font-bold">IP BANNED</span>}
                        {s.process_killed && <span className="bg-purple-100 text-purple-800 px-1.5 py-0.5 rounded text-[10px] font-bold">PROC KILLED</span>}
                        {s.network_blocked && <span className="bg-orange-100 text-orange-800 px-1.5 py-0.5 rounded text-[10px] font-bold">NET BLOCKED</span>}
                        {!s.ip_banned && !s.process_killed && !s.network_blocked && <span className="text-gray-400 text-xs">None</span>}
                      </div>
                    </td>
                  </tr>
                ))}
                {sessions.length === 0 && (
                  <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No active sessions</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Kill Chain Funnel" className="flex flex-col justify-center">
          <div className="space-y-4 px-2">
            {[1,2,3,4,5,6,7].map((stage, idx) => {
              const count = killChainCounts[idx];
              const percent = maxChainCount > 0 ? (count / maxChainCount) * 100 : 0;
              return (
                <div key={stage} className="relative">
                  <div className="flex justify-between text-xs mb-1 font-medium text-gray-600">
                    <span>{stage}. {KILL_CHAIN_STAGES[stage]}</span>
                    <span>{count}</span>
                  </div>
                  <div className="w-full bg-gray-100 rounded-sm h-3">
                    <div className="bg-indigo-500 h-3 rounded-sm transition-all" style={{ width: `${percent}%` }}></div>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      </div>
    </div>
  );
}
