import React from 'react';
import { Network, Activity, Globe, Shield, Filter } from 'lucide-react';
import { Card } from '../components/UI/Card';

interface NetworkProps {
  liveData: any;
  sessions?: any;
}

export default function NetworkPage({ liveData }: NetworkProps) {
  const { stats, sessions, alerts, blocks } = liveData;

  const networkAlerts = (alerts || [])
    .filter((a: any) => a.src_ip || a.dst_ip)
    .slice(0, 30);

  const protocolDist = networkAlerts.reduce((acc: any, alert: any) => {
    const proto = alert.proto || 'Unknown';
    if (!acc[proto]) {
      acc[proto] = { count: 0, blocked: 0 };
    }
    acc[proto].count++;
    if (alert.blocked) {
      acc[proto].blocked++;
    }
    return acc;
  }, {});

  const formatDuration = (start: string, end: string) => {
    if (!start || !end) return '-';
    const s = new Date(start).getTime();
    const e = new Date(end).getTime();
    const diff = e - s;
    if (diff < 1000) return `${diff}ms`;
    return `${(diff / 1000).toFixed(2)}s`;
  };

  const getThreatBar = (score: number) => {
    const s = Math.min(100, Math.max(0, score || 0));
    let color = 'bg-blue-500';
    if (s > 75) color = 'bg-red-500';
    else if (s > 50) color = 'bg-orange-500';
    else if (s > 25) color = 'bg-yellow-500';

    return (
      <div className="w-24 h-2 bg-gray-200 rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${s}%` }}></div>
      </div>
    );
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Network Visibility</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-blue-100 rounded-full text-blue-600">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{stats?.event_bus?.total_events?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Total Bus Events</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-purple-100 rounded-full text-purple-600">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{stats?.nexus?.active_sessions?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Active Sessions</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-green-100 rounded-full text-green-600">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{stats?.webguard?.requests_inspected?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Total Requests</div>
          </div>
        </Card>
        <Card className="p-4 flex items-center space-x-4">
          <div className="p-3 bg-red-100 rounded-full text-red-600">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{(blocks?.length || 0).toLocaleString()}</div>
            <div className="text-sm text-gray-500">IPs Blocked</div>
          </div>
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b bg-gray-50">
          <h2 className="text-lg font-bold text-gray-900">Attack Sessions</h2>
        </div>
        {sessions && sessions.length > 0 ? (
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr className="bg-gray-100 text-left text-sm text-gray-600 uppercase tracking-wider">
                <th className="p-3 font-semibold">Session ID</th>
                <th className="p-3 font-semibold">Attacker &rarr; Target</th>
                <th className="p-3 font-semibold">Events</th>
                <th className="p-3 font-semibold">Kill Chain Stage</th>
                <th className="p-3 font-semibold">Duration</th>
                <th className="p-3 font-semibold">Threat Score</th>
                <th className="p-3 font-semibold">Responses</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {sessions.map((sess: any) => (
                <tr key={sess.id} className="hover:bg-gray-50">
                  <td className="p-3 text-sm font-mono text-gray-900">{sess.id.substring(0, 8)}...</td>
                  <td className="p-3 text-sm">
                    <span className="text-red-600 font-mono">{sess.attacker_ip}</span> &rarr; <span className="text-blue-600 font-mono">{sess.target_ip}</span>
                  </td>
                  <td className="p-3 text-sm text-gray-600">{sess.event_count || 0}</td>
                  <td className="p-3 text-sm font-medium">{sess.kill_chain_stage || 'Unknown'}</td>
                  <td className="p-3 text-sm text-gray-600">{formatDuration(sess.first_event, sess.last_event)}</td>
                  <td className="p-3">{getThreatBar(sess.threat_score)}</td>
                  <td className="p-3">
                    <div className="flex gap-1">
                      {sess.responses?.map((resp: string) => (
                        <span key={resp} className="px-2 py-0.5 text-xs rounded bg-gray-200 text-gray-700">{resp}</span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        ) : (
          <div className="p-8 text-center text-gray-500 flex flex-col items-center">
            <Shield className="w-12 h-12 mb-3 text-gray-300" />
            <p>No active attack sessions.</p>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <Card className="p-0 overflow-hidden h-full">
            <div className="p-4 border-b bg-gray-50">
              <h2 className="text-lg font-bold text-gray-900">Network Alerts Feed</h2>
            </div>
            {networkAlerts.length > 0 ? (
              <div className="max-h-[400px] overflow-y-auto">
                <div className="table-container"><table className="enterprise-table"><thead>
                    <tr className="bg-gray-100 text-left text-xs text-gray-600 uppercase tracking-wider sticky top-0">
                      <th className="p-3 font-semibold">Time</th>
                      <th className="p-3 font-semibold">Protocol</th>
                      <th className="p-3 font-semibold">Src &rarr; Dst</th>
                      <th className="p-3 font-semibold">Type</th>
                      <th className="p-3 font-semibold">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {networkAlerts.map((alert: any, i: number) => (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="p-3 text-xs text-gray-500 whitespace-nowrap">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                        <td className="p-3 text-xs font-mono">{alert.proto || '-'}</td>
                        <td className="p-3 text-xs">
                          {alert.src_ip} &rarr; {alert.dst_ip}
                        </td>
                        <td className="p-3 text-xs font-medium text-gray-900">{alert.type}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 text-xs rounded-full ${
                            alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-blue-100 text-blue-800'
                          }`}>
                            {alert.severity || 'low'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table></div>
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500">
                <p>No recent network alerts.</p>
              </div>
            )}
          </Card>
        </div>
        <div>
          <Card className="p-0 overflow-hidden h-full">
            <div className="p-4 border-b bg-gray-50 flex items-center space-x-2">
              <Filter className="w-5 h-5 text-gray-500" />
              <h2 className="text-lg font-bold text-gray-900">Protocol Distribution</h2>
            </div>
            {Object.keys(protocolDist).length > 0 ? (
              <div className="table-container"><table className="enterprise-table"><thead>
                  <tr className="bg-gray-100 text-left text-xs text-gray-600 uppercase tracking-wider">
                    <th className="p-3 font-semibold">Protocol</th>
                    <th className="p-3 font-semibold text-right">Alerts</th>
                    <th className="p-3 font-semibold text-right">Blocked</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {Object.entries(protocolDist).sort((a: any, b: any) => b[1].count - a[1].count).map(([proto, data]: any) => (
                    <tr key={proto}>
                      <td className="p-3 text-sm font-medium text-gray-900">{proto}</td>
                      <td className="p-3 text-sm text-right text-gray-600">{data.count}</td>
                      <td className="p-3 text-sm text-right text-red-600">{data.blocked}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            ) : (
              <div className="p-8 text-center text-gray-500">
                <p>No protocol data available.</p>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
