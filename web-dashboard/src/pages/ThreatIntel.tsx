import React, { useState } from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { api } from '../api/client';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { Eye, AlertOctagon, Ban, Search, Plus } from 'lucide-react';

interface ThreatIntelProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
  iocs?: any;
  setIocs?: any;
  liveIOC?: any;
  liveSessions?: any;
}

export default function ThreatIntel({ liveData, addToast }: ThreatIntelProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [showAddIoc, setShowAddIoc] = useState(false);
  const [newIoc, setNewIoc] = useState({ type: 'IP', value: '', actor: '', confidence: 50 });

  const iocs = [...(liveData.ioc || [])].sort((a, b) => b.hit_count - a.hit_count);
  const blocks = liveData.blocks || [];

  const handleUnban = async (ip: string) => {
    try {
      await api.unbanIP(ip);
      addToast(`Unbanned IP: ${ip}`, 'success');
      liveData.refresh();
    } catch (e) {
      addToast('Failed to unban IP', 'error');
    }
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.addIOC({ type: newIoc.type, value: newIoc.value, actor: newIoc.actor, confidence: newIoc.confidence });
      addToast(`Added IOC: ${newIoc.value}`, 'success');
      setShowAddIoc(false);
      setNewIoc({ type: 'IP', value: '', actor: '', confidence: 50 });
      liveData.refresh();
    } catch (err) {
      addToast('Failed to add IOC', 'error');
    }
  };

  const filteredIocs = iocs.filter(ioc => {
    if (typeFilter && ioc.type !== typeFilter) return false;
    if (searchTerm && !ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) && !ioc.threat_actor?.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const actorCounts = iocs.reduce((acc, curr) => {
    if (curr.threat_actor) {
      acc[curr.threat_actor] = (acc[curr.threat_actor] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const topActors = Object.entries(actorCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
          <AlertOctagon className="w-6 h-6 text-red-600" /> Threat Intelligence
        </h1>
        <Button onClick={() => setShowAddIoc(!showAddIoc)} className="flex items-center gap-1">
          <Plus className="w-4 h-4" /> Add IOC
        </Button>
      </div>

      {showAddIoc && (
        <Card className="p-4 bg-gray-50 border-blue-100">
          <form onSubmit={handleAddIoc} className="flex flex-wrap items-end gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Type</label>
              <select className="border rounded p-2 text-sm bg-white" value={newIoc.type} onChange={e => setNewIoc({...newIoc, type: e.target.value})}>
                <option>IP</option>
                <option>Domain</option>
                <option>Hash</option>
                <option>URL</option>
              </select>
            </div>
            <div className="flex-1 min-w-[200px]">
              <label className="block text-xs font-medium text-gray-600 mb-1">Value</label>
              <input type="text" required className="border rounded p-2 text-sm w-full" value={newIoc.value} onChange={e => setNewIoc({...newIoc, value: e.target.value})} placeholder="e.g. 192.168.1.1" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Actor (Optional)</label>
              <input type="text" className="border rounded p-2 text-sm w-full" value={newIoc.actor} onChange={e => setNewIoc({...newIoc, actor: e.target.value})} placeholder="e.g. APT29" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Confidence ({newIoc.confidence}%)</label>
              <input type="range" min="1" max="100" className="w-full" value={newIoc.confidence} onChange={e => setNewIoc({...newIoc, confidence: parseInt(e.target.value)})} />
            </div>
            <Button type="submit" variant="primary">Save IOC</Button>
            <Button type="button" variant="secondary" onClick={() => setShowAddIoc(false)}>Cancel</Button>
          </form>
        </Card>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        <div className="xl:col-span-3 space-y-4">
          <Card className="flex flex-col h-full">
            <div className="p-4 border-b flex justify-between items-center bg-white">
              <h2 className="font-bold text-gray-800">IOC Database</h2>
              <div className="flex gap-2">
                <select className="border rounded px-2 py-1 text-sm text-gray-600" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
                  <option value="">All Types</option>
                  <option value="IP">IP</option>
                  <option value="Domain">Domain</option>
                  <option value="Hash">Hash</option>
                  <option value="URL">URL</option>
                </select>
                <div className="relative">
                  <Search className="w-4 h-4 absolute left-2 top-2 text-gray-400" />
                  <input type="text" placeholder="Search IOCs..." className="border rounded pl-8 pr-2 py-1 text-sm w-48" value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />
                </div>
              </div>
            </div>
            <div className="overflow-auto max-h-[600px]">
              <table className="w-full text-sm text-left">
                <thead className="bg-gray-50 text-gray-600 sticky top-0">
                  <tr>
                    <th className="px-4 py-2 font-medium">Type</th>
                    <th className="px-4 py-2 font-medium">Value</th>
                    <th className="px-4 py-2 font-medium">Threat Actor</th>
                    <th className="px-4 py-2 font-medium">Campaign</th>
                    <th className="px-4 py-2 font-medium">ATT&CK</th>
                    <th className="px-4 py-2 font-medium">Confidence</th>
                    <th className="px-4 py-2 font-medium text-right">Hits</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filteredIocs.slice(0, 100).map((ioc, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-4 py-2">
                        <span className="bg-gray-100 text-gray-700 px-2 py-1 rounded text-xs font-medium">{ioc.type}</span>
                      </td>
                      <td className="px-4 py-2 font-mono text-gray-800">{ioc.value}</td>
                      <td className="px-4 py-2 text-gray-600">{ioc.threat_actor || '-'}</td>
                      <td className="px-4 py-2 text-gray-600">{ioc.campaign || '-'}</td>
                      <td className="px-4 py-2 font-mono text-xs text-gray-500">{ioc.attck_tech || '-'}</td>
                      <td className="px-4 py-2">
                        <div className="w-full bg-gray-200 rounded-full h-1.5 mt-1">
                          <div className={`h-1.5 rounded-full ${ioc.confidence > 80 ? 'bg-red-500' : ioc.confidence > 50 ? 'bg-orange-500' : 'bg-blue-500'}`} style={{ width: `${ioc.confidence}%` }}></div>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-right font-bold">{ioc.hit_count.toLocaleString()}</td>
                    </tr>
                  ))}
                  {filteredIocs.length === 0 && (
                    <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No IOCs found</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          <Card className="max-h-[350px] flex flex-col">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
              <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>Active Blocks</span>
              <span style={{ background: '#ef444422', color: '#ef4444', border: '1px solid #ef444444', borderRadius: 12, padding: '1px 8px', fontSize: '0.75rem', fontWeight: 700 }}>{blocks.length}</span>
            </div>
            <div className="overflow-auto p-2">
              {blocks.length === 0 ? (
                <div className="text-center py-6 text-gray-500 text-sm">No active blocks</div>
              ) : (
                <div className="space-y-2">
                  {blocks.map(ip => (
                    <div key={ip} className="flex justify-between items-center p-2 hover:bg-gray-50 border rounded border-gray-100">
                      <div className="flex items-center gap-2">
                        <Ban className="w-4 h-4 text-red-500" />
                        <span className="font-mono text-sm">{ip}</span>
                      </div>
                      <button onClick={() => handleUnban(ip)} className="text-xs text-blue-600 hover:text-blue-800 font-medium">Unban</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>

          <Card title="Top Threat Actors">
            <div className="p-4 space-y-3">
              {topActors.length === 0 ? (
                <div className="text-sm text-gray-500 text-center">No actor data</div>
              ) : (
                topActors.map(([actor, count], i) => (
                  <div key={actor} className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded-full bg-gray-100 text-gray-500 flex items-center justify-center text-xs font-bold">{i + 1}</div>
                      <span className="font-medium text-gray-800 text-sm">{actor}</span>
                    </div>
                    <span className="text-xs font-bold bg-gray-100 px-2 py-1 rounded">{count}</span>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
