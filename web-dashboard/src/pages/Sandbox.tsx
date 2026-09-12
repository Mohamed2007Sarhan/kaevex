import React from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { Card } from '../components/UI/Card';
import { Box, Network, Shield, Activity } from 'lucide-react';

interface SandboxProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
  sessions?: any;
  setSessions?: any;
}

const formatBytes = (bytes: number) => {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function Sandbox({ liveData }: SandboxProps) {
  const sb = liveData.stats?.sandbox;
  const sandboxes = liveData.sandboxList || [];
  const logs = liveData.proxyLogs || [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
          <Box className="w-6 h-6 text-indigo-600" /> Sandbox Orchestration
        </h1>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card className="p-4 flex flex-col justify-center items-center">
          <Box className="w-8 h-8 text-blue-500 mb-2 opacity-80"/>
          <div className="text-2xl font-bold text-gray-800">{sb?.sandbox_count || 0}</div>
          <div className="text-xs text-gray-500 uppercase tracking-wider">Active Sandboxes</div>
        </Card>
        <Card className="p-4 flex flex-col justify-center items-center">
          <Activity className="w-8 h-8 text-green-500 mb-2 opacity-80"/>
          <div className="text-lg font-bold mt-1">
            {sb?.proxy_running ? 
              <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-sm">Active</span> : 
              <span className="bg-gray-100 text-gray-800 px-2 py-1 rounded text-sm">Inactive</span>}
          </div>
          <div className="text-xs text-gray-500 uppercase tracking-wider mt-2">Proxy Status</div>
        </Card>
        <Card className="p-4 flex flex-col justify-center items-center">
          <Network className="w-8 h-8 text-purple-500 mb-2 opacity-80"/>
          <div className="text-2xl font-bold text-gray-800">{sb?.proxy_port || '-'}</div>
          <div className="text-xs text-gray-500 uppercase tracking-wider">Proxy Port</div>
        </Card>
        <Card className="p-4 flex flex-col justify-center items-center">
          <Shield className="w-8 h-8 text-indigo-500 mb-2 opacity-80"/>
          <div className="text-2xl font-bold text-gray-800">{sb?.total_connections?.toLocaleString() || 0}</div>
          <div className="text-xs text-gray-500 uppercase tracking-wider">Total Connections</div>
        </Card>
        <Card className="p-4 flex flex-col justify-center items-center">
          <Network className="w-8 h-8 text-orange-500 mb-2 opacity-80"/>
          <div className="text-xl font-bold text-gray-800">{formatBytes(sb?.total_bytes_sent || 0)}</div>
          <div className="text-xs text-gray-500 uppercase tracking-wider">Bytes Sent</div>
        </Card>
        <Card className="p-4 flex flex-col justify-center items-center">
          <Network className="w-8 h-8 text-teal-500 mb-2 opacity-80"/>
          <div className="text-xl font-bold text-gray-800">{formatBytes(sb?.total_bytes_recv || 0)}</div>
          <div className="text-xs text-gray-500 uppercase tracking-wider">Bytes Recv</div>
        </Card>
      </div>

      <Card title="Active Sandboxes">
        {sandboxes.length === 0 ? (
          <div className="py-12 flex flex-col items-center justify-center text-gray-500">
            <Box className="w-16 h-16 mb-4 text-gray-300" />
            <p className="text-lg">No active sandboxes.</p>
            <p className="text-sm">Launch a sandbox to begin monitoring.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-gray-50 text-gray-600 border-b border-gray-100">
                <tr>
                  <th className="px-4 py-3 font-medium">Name</th>
                  <th className="px-4 py-3 font-medium">State</th>
                  <th className="px-4 py-3 font-medium">PID</th>
                  <th className="px-4 py-3 font-medium">Executable</th>
                  <th className="px-4 py-3 font-medium">Started</th>
                  <th className="px-4 py-3 font-medium">Firewall</th>
                  <th className="px-4 py-3 font-medium">Integrity</th>
                  <th className="px-4 py-3 font-medium">Traffic (S/R)</th>
                  <th className="px-4 py-3 font-medium">Conn</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {sandboxes.map((s, i) => (
                  <tr key={i} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-800">{s.name}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        s.state.toLowerCase() === 'running' ? 'bg-green-100 text-green-800' :
                        s.state.toLowerCase() === 'paused' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {s.state}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{s.pid}</td>
                    <td className="px-4 py-3 font-mono text-xs truncate max-w-[150px]" title={s.exe}>{s.exe.split('\\').pop() || s.exe.split('/').pop()}</td>
                    <td className="px-4 py-3 text-gray-500">{new Date(s.start_time).toLocaleTimeString()}</td>
                    <td className="px-4 py-3">
                      {s.firewall_active ? 
                        <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs">Active</span> : 
                        <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">Off</span>}
                    </td>
                    <td className="px-4 py-3">
                      {s.low_integrity ? 
                        <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-xs">Low</span> : 
                        <span className="bg-gray-100 text-gray-800 px-2 py-1 rounded text-xs">Normal</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {formatBytes(s.bytes_sent)} / {formatBytes(s.bytes_recv)}
                    </td>
                    <td className="px-4 py-3 font-medium">{s.connections}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Proxy Traffic Log (Last 50)" className="overflow-hidden">
        <div className="overflow-auto max-h-[400px]">
          <table className="w-full text-sm text-left">
            <thead className="bg-gray-50 text-gray-600 sticky top-0">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Method</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Port</th>
                <th className="px-4 py-2 font-medium">Sandbox</th>
                <th className="px-4 py-2 font-medium">Blocked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {logs.slice(0, 50).map((log, i) => (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-2 whitespace-nowrap text-gray-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-2 font-mono text-xs">{log.method}</td>
                  <td className="px-4 py-2">{log.host}</td>
                  <td className="px-4 py-2 text-gray-600">{log.port}</td>
                  <td className="px-4 py-2 font-medium text-gray-700">{log.sandbox}</td>
                  <td className="px-4 py-2">
                    {log.was_blocked ? 
                      <span className="bg-red-100 text-red-800 px-2 py-0.5 rounded text-xs font-medium">Yes</span> : 
                      <span className="bg-green-100 text-green-800 px-2 py-0.5 rounded text-xs font-medium">No</span>}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No proxy logs available</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
