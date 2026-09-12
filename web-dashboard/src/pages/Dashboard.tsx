import React from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { 
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  WifiOff, 
  ShieldAlert, 
  Shield, 
  Activity, 
  Ban, 
  Search, 
  Bug,
  Server,
  Cpu,
  Globe,
  Database
} from 'lucide-react';

interface DashboardProps {
  liveData: AegisLiveData;
  onNavigate: (page: string) => void;
}

const styles = {
  container: { padding: '20px', display: 'flex', flexDirection: 'column' as const, gap: '20px', color: 'hsl(var(--text-primary))' },
  loadingContainer: { display: 'flex', gap: '20px', flexWrap: 'wrap' as const, padding: '20px' },
  skeleton: { backgroundColor: 'hsl(var(--bg-secondary))', height: '100px', flex: '1 1 30%', borderRadius: '8px', animation: 'pulse 1.5s infinite' },
  offlineBanner: { display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: 'hsl(var(--bg-secondary))', padding: '20px', borderRadius: '8px', border: '1px solid red' },
  statusRow: { display: 'flex', gap: '10px', flexWrap: 'wrap' as const, backgroundColor: 'hsl(var(--bg-secondary))', padding: '15px', borderRadius: '8px' },
  statusPill: { display: 'flex', alignItems: 'center', gap: '5px', padding: '5px 10px', borderRadius: '15px', fontSize: '0.85rem', fontWeight: 'bold' },
  kpiGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' },
  kpiCard: { cursor: 'pointer', display: 'flex', flexDirection: 'column' as const, alignItems: 'center', gap: '10px', padding: '20px', backgroundColor: 'hsl(var(--bg-secondary))', borderRadius: '8px', transition: 'transform 0.2s' },
  kpiValue: { fontSize: '2rem', fontWeight: 'bold', color: 'hsl(var(--accent-color))' },
  kpiLabel: { fontSize: '0.9rem', color: 'hsl(var(--text-primary))', opacity: 0.8 },
  miniGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '10px' },
  miniCard: { display: 'flex', alignItems: 'center', gap: '10px', padding: '15px', backgroundColor: 'hsl(var(--bg-secondary))', borderRadius: '8px' },
  badge: { padding: '3px 8px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', color: '#fff' }
};

export default function Dashboard({ liveData, onNavigate }: DashboardProps) {
  if (liveData.loading) {
    return (
      <div style={styles.loadingContainer}>
        <div style={styles.skeleton}></div>
        <div style={styles.skeleton}></div>
        <div style={styles.skeleton}></div>
        <div style={styles.skeleton}></div>
      </div>
    );
  }

  if (!liveData.connected) {
    return (
      <div style={styles.container}>
        <div style={styles.offlineBanner}>
          <WifiOff size={32} color="red" />
          <h2>Connection Offline</h2>
          <p>Unable to connect to AegisCore live backend.</p>
        </div>
      </div>
    );
  }

  const engineStatus = liveData.status?.engines || {};
  const activeIncidents = liveData.incidents.filter(i => !i.auto_remediated).length;
  const totalAlerts = liveData.alerts.length;

  const renderStatusIcon = (status: string) => {
    if (status.toLowerCase() === 'online') return <CheckCircle size={16} color="green" />;
    if (status.toLowerCase() === 'offline') return <XCircle size={16} color="red" />;
    return <AlertCircle size={16} color="orange" />;
  };

  const recentAlerts = liveData.alerts.slice(-8).reverse();

  const getSeverityColor = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'red';
    if (s === 'high') return 'orange';
    if (s === 'medium') return 'goldenrod';
    return 'gray';
  };

  return (
    <div style={styles.container}>
      {/* Status bar */}
      <div style={styles.statusRow}>
        {Object.entries(engineStatus).map(([engine, status]) => (
          <div key={engine} style={{ ...styles.statusPill, border: `1px solid ${status.toLowerCase() === 'online' ? 'green' : status.toLowerCase() === 'offline' ? 'red' : 'orange'}` }}>
            {renderStatusIcon(status)}
            <span>{engine.toUpperCase()}</span>
          </div>
        ))}
      </div>

      {/* KPI Cards */}
      <div style={styles.kpiGrid}>
        <div style={styles.kpiCard} onClick={() => onNavigate('intrusion')}>
          <ShieldAlert size={32} color={totalAlerts > 10 ? 'red' : 'hsl(var(--accent-color))'} />
          <div style={{ ...styles.kpiValue, color: totalAlerts > 10 ? 'red' : 'hsl(var(--accent-color))' }}>{totalAlerts}</div>
          <div style={styles.kpiLabel}>Total Alerts</div>
        </div>
        <div style={styles.kpiCard} onClick={() => onNavigate('intrusion')}>
          <Shield size={32} color="hsl(var(--accent-color))" />
          <div style={styles.kpiValue}>{liveData.stats?.webguard.requests_blocked ?? 0}</div>
          <div style={styles.kpiLabel}>Threats Blocked</div>
        </div>
        <div style={styles.kpiCard} onClick={() => onNavigate('nexus')}>
          <Activity size={32} color="hsl(var(--accent-color))" />
          <div style={styles.kpiValue}>{activeIncidents}</div>
          <div style={styles.kpiLabel}>Active Incidents</div>
        </div>
        <div style={styles.kpiCard} onClick={() => onNavigate('intrusion')}>
          <Ban size={32} color="hsl(var(--accent-color))" />
          <div style={styles.kpiValue}>{liveData.stats?.webguard.ips_banned ?? 0}</div>
          <div style={styles.kpiLabel}>IPs Banned</div>
        </div>
        <div style={styles.kpiCard} onClick={() => onNavigate('host')}>
          <Search size={32} color="hsl(var(--accent-color))" />
          <div style={styles.kpiValue}>{liveData.stats?.av.files_scanned ?? 0}</div>
          <div style={styles.kpiLabel}>Files Scanned</div>
        </div>
        <div style={styles.kpiCard} onClick={() => onNavigate('host')}>
          <Bug size={32} color="hsl(var(--accent-color))" />
          <div style={styles.kpiValue}>{liveData.stats?.hostguard.stat_cve_found ?? 0}</div>
          <div style={styles.kpiLabel}>CVEs Found</div>
        </div>
      </div>

      {/* Engine health mini-grid */}
      <h3>Engine Health & Statistics</h3>
      <div style={styles.miniGrid}>
        <div style={styles.miniCard}><Globe size={24} /> <div><strong>WAF</strong><br/>{liveData.stats?.webguard.requests_inspected ?? 0} Inspected</div></div>
        <div style={styles.miniCard}><Shield size={24} /> <div><strong>AV</strong><br/>{liveData.stats?.av.threats_found ?? 0} Found</div></div>
        <div style={styles.miniCard}><Activity size={24} /> <div><strong>Nexus</strong><br/>{liveData.stats?.nexus.incidents_created ?? 0} Incidents</div></div>
        <div style={styles.miniCard}><Cpu size={24} /> <div><strong>HostGuard</strong><br/>{liveData.stats?.hostguard.stat_cve_found ?? 0} CVEs</div></div>
        <div style={styles.miniCard}><Server size={24} /> <div><strong>Sandbox</strong><br/>{liveData.stats?.sandbox.sandbox_count ?? 0} Analyzed</div></div>
        <div style={styles.miniCard}><Database size={24} /> <div><strong>Bus</strong><br/>{liveData.status?.total_bus_events ?? 0} Events</div></div>
      </div>

      {/* Recent Alerts */}
      <h3>Recent Alerts</h3>
      <Card>
        <div className="table-container"><table className="enterprise-table"><thead>
            <tr>
              <th>Time</th>
              <th>Engine</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Src IP</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {recentAlerts.map(alert => (
              <tr key={alert.id}>
                <td>{new Date(alert.timestamp).toLocaleString()}</td>
                <td>{alert.engine}</td>
                <td>{alert.type}</td>
                <td>
                  <span style={{ ...styles.badge, backgroundColor: getSeverityColor(alert.severity) }}>
                    {alert.severity.toUpperCase()}
                  </span>
                </td>
                <td>{alert.src_ip}</td>
                <td>
                  <span style={{ ...styles.badge, backgroundColor: alert.blocked ? 'green' : 'red' }}>
                    {alert.blocked ? 'BLOCKED' : 'ACTIVE'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </Card>
    </div>
  );
}
