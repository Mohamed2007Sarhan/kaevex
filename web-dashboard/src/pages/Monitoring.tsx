import React from 'react';
import { Activity, RefreshCw, Cpu, Server, Shield, Box, Network, Zap } from 'lucide-react';
import { Card } from '../components/UI/Card';

interface MonitoringProps {
  liveData: any;
  addToast?: any;
}

export default function Monitoring({ liveData, addToast }: MonitoringProps) {
  const { stats, lastUpdate, loading, connected } = liveData;

  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getCapacityPercent = (total?: number, capacity?: number) => {
    if (!total || !capacity || capacity === 0) return 0;
    return Math.min(100, Math.round((total / capacity) * 100));
  };

  const eventTotal = stats?.event_bus?.total_events || 0;
  const eventCapacity = stats?.event_bus?.capacity || 1;
  const capacityPercent = getCapacityPercent(eventTotal, eventCapacity);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">System Monitoring</h1>
        <div className="flex items-center space-x-3 text-sm text-gray-500">
          <span className="flex items-center space-x-2">
            <span>Status:</span>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span>{connected ? 'Connected' : 'Disconnected'}</span>
          </span>
          {lastUpdate && (
            <span className="flex items-center space-x-1">
              <span>Last update: {lastUpdate.toLocaleTimeString()}</span>
              {loading && <RefreshCw className="w-4 h-4 animate-spin text-blue-500" />}
            </span>
          )}
        </div>
      </div>

      <Card className="p-6 border-l-4 border-blue-500">
        <div className="flex items-center space-x-4 mb-4">
          <Activity className="w-8 h-8 text-blue-500" />
          <div>
            <h2 className="text-xl font-bold text-gray-900">Event Bus</h2>
            <p className="text-sm text-gray-500">Global messaging pipeline capacity</p>
          </div>
        </div>
        <div className="space-y-4">
          <div className="flex justify-between items-end">
            <div>
              <div className="text-4xl font-bold text-gray-900">{eventTotal.toLocaleString()}</div>
              <div className="text-sm font-medium text-gray-500">Total Events Processed</div>
            </div>
            <div className="text-right">
              <div className="text-lg font-bold text-gray-900">{capacityPercent}%</div>
              <div className="text-sm font-medium text-gray-500">Capacity Utilization</div>
            </div>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5">
            <div 
              className={`h-2.5 rounded-full ${capacityPercent > 90 ? 'bg-red-500' : capacityPercent > 70 ? 'bg-yellow-500' : 'bg-blue-500'}`}
              style={{ width: `${capacityPercent}%` }}
            ></div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* AV Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Activity className="w-5 h-5 text-indigo-500" />
            <h3 className="font-bold text-gray-900">Anti-Virus</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Total Scans</span>
              <span className="font-semibold">{stats?.av?.total_scans?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Files Scanned</span>
              <span className="font-semibold">{stats?.av?.files_scanned?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Threats Found</span>
              <span className="font-semibold text-red-600">{stats?.av?.threats_found?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">Realtime</span>
              <span className={`text-xs px-2 py-1 rounded-full ${stats?.av?.realtime_enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                {stats?.av?.realtime_enabled ? 'Active' : 'Inactive'}
              </span>
            </div>
          </div>
        </Card>

        {/* WebGuard Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Shield className="w-5 h-5 text-emerald-500" />
            <h3 className="font-bold text-gray-900">WebGuard</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Requests</span>
              <span className="font-semibold">{stats?.webguard?.requests_inspected?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Blocked</span>
              <span className="font-semibold text-orange-600">{stats?.webguard?.requests_blocked?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Attacks</span>
              <span className="font-semibold text-red-600">{stats?.webguard?.attacks_detected?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Profile</span>
              <span className="font-semibold">{stats?.webguard?.profile || 'N/A'}</span>
            </div>
          </div>
        </Card>

        {/* Nexus Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Network className="w-5 h-5 text-purple-500" />
            <h3 className="font-bold text-gray-900">Nexus</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Events</span>
              <span className="font-semibold">{stats?.nexus?.events_processed?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Active Sessions</span>
              <span className="font-semibold">{stats?.nexus?.active_sessions?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Incidents</span>
              <span className="font-semibold text-red-600">{stats?.nexus?.incidents_created?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Dedup Dropped</span>
              <span className="font-semibold">{stats?.nexus?.dedup_dropped?.toLocaleString() || 0}</span>
            </div>
          </div>
        </Card>

        {/* HostGuard Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Cpu className="w-5 h-5 text-amber-500" />
            <h3 className="font-bold text-gray-900">HostGuard</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Components Scanned</span>
              <span className="font-semibold">{stats?.hostguard?.stat_components_scanned?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">CVEs Found</span>
              <span className="font-semibold text-red-600">{stats?.hostguard?.stat_cve_found?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Thread Restarts</span>
              <span className="font-semibold">{stats?.hostguard?.stat_thread_restarts?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Events Published</span>
              <span className="font-semibold">{stats?.hostguard?.stat_fire_events_published?.toLocaleString() || 0}</span>
            </div>
          </div>
        </Card>

        {/* Sandbox Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Box className="w-5 h-5 text-cyan-500" />
            <h3 className="font-bold text-gray-900">Sandbox</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Total Run</span>
              <span className="font-semibold">{stats?.sandbox?.sandbox_count?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Connections</span>
              <span className="font-semibold">{stats?.sandbox?.total_connections?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Data Sent</span>
              <span className="font-semibold">{formatBytes(stats?.sandbox?.total_bytes_sent)}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">Proxy</span>
              <span className={`text-xs px-2 py-1 rounded-full ${stats?.sandbox?.proxy_running ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                {stats?.sandbox?.proxy_running ? 'Running' : 'Stopped'}
              </span>
            </div>
          </div>
        </Card>

        {/* Integration Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Zap className="w-5 h-5 text-yellow-500" />
            <h3 className="font-bold text-gray-900">Integration</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">FIM to AV</span>
              <span className="font-semibold">{stats?.integration?.fim_to_av_scans?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">TLS to Hash</span>
              <span className="font-semibold">{stats?.integration?.tls_to_hash_checks?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Malware to Bans</span>
              <span className="font-semibold">{stats?.integration?.malware_to_bans?.toLocaleString() || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Realtime Blocks</span>
              <span className="font-semibold">{stats?.integration?.realtime_blocks?.toLocaleString() || 0}</span>
            </div>
          </div>
        </Card>

        {/* API Stats */}
        <Card className="p-4">
          <div className="flex items-center space-x-2 mb-4">
            <Server className="w-5 h-5 text-gray-500" />
            <h3 className="font-bold text-gray-900">API Gateway</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-500">Requests Served</span>
              <span className="font-semibold">{stats?.api?.requests_served?.toLocaleString() || 0}</span>
            </div>
          </div>
        </Card>
      </div>
      
      <div className="pt-6">
        <h2 className="text-lg font-bold text-gray-900 mb-4">System Trends</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded border">
            <div className="text-3xl font-black text-gray-900">{stats?.av?.threats_quarantined?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Threats Quarantined</div>
          </div>
          <div className="bg-white p-4 rounded border">
            <div className="text-3xl font-black text-gray-900">{stats?.webguard?.ips_banned?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">IPs Banned</div>
          </div>
          <div className="bg-white p-4 rounded border">
            <div className="text-3xl font-black text-gray-900">{stats?.nexus?.ioc_hits?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">IOC Hits</div>
          </div>
          <div className="bg-white p-4 rounded border">
            <div className="text-3xl font-black text-gray-900">{stats?.hostguard?.stat_remediations_applied?.toLocaleString() || 0}</div>
            <div className="text-sm text-gray-500">Auto-Remediations</div>
          </div>
        </div>
      </div>
    </div>
  );
}
