import React from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { api } from '../api/client';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { Monitor, Shield, AlertTriangle, Cpu, Package, RefreshCw, Activity, WifiOff } from 'lucide-react';

interface HostSecurityProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
}

const styles = {
  container: { padding: '20px', display: 'flex', flexDirection: 'column' as const, gap: '20px', color: 'hsl(var(--text-primary))' },
  loadingContainer: { display: 'flex', gap: '20px', flexWrap: 'wrap' as const, padding: '20px' },
  skeleton: { backgroundColor: 'hsl(var(--bg-secondary))', height: '100px', flex: '1 1 30%', borderRadius: '8px', animation: 'pulse 1.5s infinite' },
  offlineBanner: { display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: 'hsl(var(--bg-secondary))', padding: '20px', borderRadius: '8px', border: '1px solid red' },
  warningBanner: { display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: 'rgba(255, 0, 0, 0.1)', padding: '20px', borderRadius: '8px', border: '2px solid red', color: 'red' },
  statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' },
  statCard: { padding: '20px', backgroundColor: 'hsl(var(--bg-secondary))', borderRadius: '8px', display: 'flex', flexDirection: 'column' as const, alignItems: 'center', gap: '10px' },
  statValue: { fontSize: '1.8rem', fontWeight: 'bold', color: 'hsl(var(--accent-color))' },
  statLabel: { fontSize: '0.85rem', opacity: 0.8, textAlign: 'center' as const },
  badge: { padding: '4px 8px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', color: '#fff' }
};

export default function HostSecurity({ liveData, addToast }: HostSecurityProps) {
  if (liveData.loading) {
    return (
      <div style={styles.loadingContainer}>
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

  const handleForceScan = async () => {
    try {
      await api.hostguardForceScan();
      addToast('HostGuard scan initiated', 'success');
    } catch (e) {
      addToast('Failed to initiate scan', 'error');
    }
  };

  const hgStats = liveData.stats?.hostguard;
  const rwStats = liveData.ransomware;
  const hpStats = liveData.honeypots;

  return (
    <div style={styles.container}>
      {rwStats?.currently_locked_down && (
        <div style={styles.warningBanner}>
          <AlertTriangle size={32} />
          <div>
            <h2 style={{ margin: 0 }}>Ransomware Lockdown Active</h2>
            <p style={{ margin: 0, marginTop: '5px' }}>Critical ransomware activity detected. Defensive measures are actively isolating threats.</p>
          </div>
        </div>
      )}

      <h3>HostGuard Statistics</h3>
      <div style={styles.statsGrid}>
        <div style={styles.statCard}>
          <Package size={28} color="hsl(var(--accent-color))" />
          <div style={styles.statValue}>{hgStats?.stat_components_scanned ?? 0}</div>
          <div style={styles.statLabel}>Components Scanned</div>
        </div>
        <div style={styles.statCard}>
          <AlertTriangle size={28} color="red" />
          <div style={styles.statValue}>{hgStats?.stat_cve_found ?? 0}</div>
          <div style={styles.statLabel}>CVEs Found</div>
        </div>
        <div style={styles.statCard}>
          <Shield size={28} color="hsl(var(--accent-color))" />
          <div style={styles.statValue}>{hgStats?.stat_remediations_applied ?? 0}</div>
          <div style={styles.statLabel}>Remediations Applied</div>
        </div>
        <div style={styles.statCard}>
          <Monitor size={28} color="hsl(var(--accent-color))" />
          <div style={styles.statValue}>{hgStats?.stat_firewall_rules_added ?? 0}</div>
          <div style={styles.statLabel}>FW Rules Added</div>
        </div>
        <div style={styles.statCard}>
          <Activity size={28} color="orange" />
          <div style={styles.statValue}>{hgStats?.stat_processes_killed ?? 0}</div>
          <div style={styles.statLabel}>Processes Killed</div>
        </div>
        <div style={styles.statCard}>
          <AlertTriangle size={28} color="darkred" />
          <div style={styles.statValue}>{rwStats?.total_detections ?? 0}</div>
          <div style={styles.statLabel}>Ransomware Detections</div>
        </div>
      </div>

      <h3>Engine Threads</h3>
      <Card>
        <div style={{ padding: '15px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Active background protection threads</span>
          <Button onClick={handleForceScan}><RefreshCw size={14} /> Force Scan</Button>
        </div>
        <div className="table-container"><table className="enterprise-table"><thead>
            <tr>
              <th>Thread Name</th>
              <th>Status</th>
              <th>Last Heartbeat</th>
              <th>Restarts</th>
            </tr>
          </thead>
          <tbody>
            {liveData.hgThreads.map(thread => (
              <tr key={thread.id}>
                <td>{thread.name}</td>
                <td>
                  <span style={{ ...styles.badge, backgroundColor: thread.alive ? 'green' : 'red' }}>
                    {thread.alive ? 'ALIVE' : 'DEAD'}
                  </span>
                </td>
                <td>{thread.last_heartbeat_age_s}s ago</td>
                <td>{thread.restart_count}</td>
              </tr>
            ))}
            {liveData.hgThreads.length === 0 && (
              <tr><td colSpan={4} style={{ textAlign: 'center' }}>No threads reported.</td></tr>
            )}
          </tbody>
        </table></div>
      </Card>

      <h3>Ransomware & Deception</h3>
      <div style={styles.statsGrid}>
        <div style={styles.statCard}>
          <Activity size={28} color="red" />
          <div style={styles.statValue}>{rwStats?.processes_killed ?? 0}</div>
          <div style={styles.statLabel}>RW Processes Killed</div>
        </div>
        <div style={styles.statCard}>
          <Shield size={28} color="green" />
          <div style={styles.statValue}>{hpStats?.count ?? 0}</div>
          <div style={styles.statLabel}>Active Honeypots</div>
        </div>
        <div style={styles.statCard}>
          <Monitor size={28} color="hsl(var(--accent-color))" />
          <div style={styles.statValue}>{rwStats?.currently_locked_down ? 'YES' : 'NO'}</div>
          <div style={styles.statLabel}>Lockdown Status</div>
        </div>
      </div>

      <h3>Installed Software & CVEs</h3>
      <Card>
        <div className="table-container"><table className="enterprise-table"><thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Type</th>
              <th>OS</th>
              <th>First Seen</th>
              <th>Needs CVE Check</th>
            </tr>
          </thead>
          <tbody>
            {liveData.hgComponents.slice(0, 20).map(comp => (
              <tr key={comp.db_id}>
                <td>{comp.name}</td>
                <td>{comp.version}</td>
                <td>{comp.type}</td>
                <td>{comp.os_info}</td>
                <td>{new Date(comp.first_seen).toLocaleDateString()}</td>
                <td>
                  <span style={{ ...styles.badge, backgroundColor: comp.needs_cve_check ? 'orange' : 'green' }}>
                    {comp.needs_cve_check ? 'YES' : 'NO'}
                  </span>
                </td>
              </tr>
            ))}
            {liveData.hgComponents.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center' }}>No software components reported.</td></tr>
            )}
          </tbody>
        </table></div>
      </Card>
    </div>
  );
}
