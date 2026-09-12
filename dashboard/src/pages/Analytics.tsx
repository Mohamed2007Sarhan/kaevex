import React from 'react';
import { BarChart3, Shield, Activity, TrendingUp, Zap } from 'lucide-react';
import { Card } from '../components/UI/Card';

interface AnalyticsProps {
  liveData: any;
}

export default function Analytics({ liveData }: AnalyticsProps) {
  const { stats, alerts } = liveData;

  const uptimeSeconds = stats?.status?.uptime_seconds || 0;
  const days = Math.floor(uptimeSeconds / (24 * 3600));
  const hours = Math.floor((uptimeSeconds % (24 * 3600)) / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = uptimeSeconds % 60;
  const formattedUptime = `${days}d ${hours}h ${minutes}m ${seconds}s`;

  const unblockedAlertsCount = (alerts || []).filter((a: any) => !a.blocked).length;
  const securityScore = Math.max(0, Math.min(100, 100 - (unblockedAlertsCount * 2)));
  
  let scoreLabel = '';
  let scoreColor = '';
  if (securityScore >= 90) { scoreLabel = 'Excellent'; scoreColor = 'text-green-500'; }
  else if (securityScore >= 70) { scoreLabel = 'Good'; scoreColor = 'text-blue-500'; }
  else if (securityScore >= 50) { scoreLabel = 'Fair'; scoreColor = 'text-yellow-500'; }
  else { scoreLabel = 'At Risk'; scoreColor = 'text-red-500'; }

  const attackTypes = (alerts || []).reduce((acc: any, alert: any) => {
    const type = alert.type || 'Unknown';
    if (!acc[type]) acc[type] = { count: 0, blocked: 0, unblocked: 0 };
    acc[type].count++;
    if (alert.blocked) acc[type].blocked++;
    else acc[type].unblocked++;
    return acc;
  }, {});
  
  const sortedAttacks = Object.entries(attackTypes).sort((a: any, b: any) => b[1].count - a[1].count);

  const webguardInspected = stats?.webguard?.requests_inspected || 0;
  const webguardBlocked = stats?.webguard?.requests_blocked || 0;
  const wgRate = webguardInspected > 0 ? ((webguardBlocked / webguardInspected) * 100).toFixed(2) + '%' : '0%';

  const avScanned = stats?.av?.files_scanned || 0;
  const avFound = stats?.av?.threats_found || 0;
  const avRate = avScanned > 0 ? ((avFound / avScanned) * 100).toFixed(4) + '%' : '0%';

  const integrationData = stats?.integration || {};

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Analytics & Statistics</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="p-6">
          <h2 className="text-lg font-bold text-gray-900 mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-blue-500" />
            Platform Overview
          </h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center border-b pb-2">
              <span className="text-gray-500">System Uptime</span>
              <span className="font-mono text-gray-900 font-medium">{formattedUptime}</span>
            </div>
            <div className="flex justify-between items-center border-b pb-2">
              <span className="text-gray-500">API Requests</span>
              <span className="font-semibold text-gray-900">{stats?.api?.requests_served?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-500">Engine Version</span>
              <span className="font-mono text-gray-900 bg-gray-100 px-2 py-1 rounded text-sm">{stats?.status?.version || 'Unknown'}</span>
            </div>
          </div>
        </Card>

        <Card className="p-6 flex flex-col justify-center items-center text-center">
          <Shield className={`w-12 h-12 mb-4 ${scoreColor}`} />
          <div className={`text-6xl font-black ${scoreColor}`}>{securityScore}</div>
          <div className="text-xl font-bold text-gray-900 mt-2">Security Score</div>
          <div className={`text-lg font-medium mt-1 ${scoreColor}`}>{scoreLabel}</div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-0 overflow-hidden">
          <div className="p-4 border-b bg-gray-50 flex items-center">
            <BarChart3 className="w-5 h-5 mr-2 text-purple-500" />
            <h2 className="text-lg font-bold text-gray-900">Attack Breakdown</h2>
          </div>
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr className="bg-gray-100 text-left text-xs text-gray-600 uppercase tracking-wider">
                <th className="p-3 font-semibold">Type</th>
                <th className="p-3 font-semibold text-right">Total Count</th>
                <th className="p-3 font-semibold text-right">Blocked</th>
                <th className="p-3 font-semibold text-right">Unblocked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sortedAttacks.length > 0 ? sortedAttacks.map(([type, data]: any) => (
                <tr key={type} className="hover:bg-gray-50">
                  <td className="p-3 text-sm font-medium text-gray-900">{type}</td>
                  <td className="p-3 text-sm text-right text-gray-600">{data.count}</td>
                  <td className="p-3 text-sm text-right text-green-600">{data.blocked}</td>
                  <td className="p-3 text-sm text-right text-red-600">{data.unblocked}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-gray-500">No attack data available.</td>
                </tr>
              )}
            </tbody>
          </table></div>
        </Card>

        <Card className="p-0 overflow-hidden">
          <div className="p-4 border-b bg-gray-50 flex items-center">
            <TrendingUp className="w-5 h-5 mr-2 text-green-500" />
            <h2 className="text-lg font-bold text-gray-900">Engine Performance</h2>
          </div>
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr className="bg-gray-100 text-left text-xs text-gray-600 uppercase tracking-wider">
                <th className="p-3 font-semibold">Engine</th>
                <th className="p-3 font-semibold">Key Metric</th>
                <th className="p-3 font-semibold text-right">Value</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              <tr className="hover:bg-gray-50">
                <td className="p-3 text-sm font-medium text-gray-900">WebGuard</td>
                <td className="p-3 text-sm text-gray-500">Block Rate</td>
                <td className="p-3 text-sm text-right font-semibold">{wgRate}</td>
              </tr>
              <tr className="hover:bg-gray-50">
                <td className="p-3 text-sm font-medium text-gray-900">Anti-Virus</td>
                <td className="p-3 text-sm text-gray-500">Detection Rate</td>
                <td className="p-3 text-sm text-right font-semibold">{avRate}</td>
              </tr>
              <tr className="hover:bg-gray-50">
                <td className="p-3 text-sm font-medium text-gray-900">Nexus</td>
                <td className="p-3 text-sm text-gray-500">Events / Incidents</td>
                <td className="p-3 text-sm text-right font-semibold">
                  {stats?.nexus?.events_processed || 0} / {stats?.nexus?.incidents_created || 0}
                </td>
              </tr>
              <tr className="hover:bg-gray-50">
                <td className="p-3 text-sm font-medium text-gray-900">HostGuard</td>
                <td className="p-3 text-sm text-gray-500">Scans / CVEs</td>
                <td className="p-3 text-sm text-right font-semibold">
                  {stats?.hostguard?.stat_components_scanned || 0} / {stats?.hostguard?.stat_cve_found || 0}
                </td>
              </tr>
            </tbody>
          </table></div>
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b bg-gray-50 flex items-center">
          <Zap className="w-5 h-5 mr-2 text-yellow-500" />
          <h2 className="text-lg font-bold text-gray-900">Integration Metrics</h2>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            {Object.entries(integrationData).map(([key, val]: any) => (
              <div key={key} className="bg-white border rounded p-3 text-center">
                <div className="text-xl font-bold text-gray-900">{val?.toLocaleString() || 0}</div>
                <div className="text-xs text-gray-500 uppercase mt-1">{key.replace(/_/g, ' ')}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}
