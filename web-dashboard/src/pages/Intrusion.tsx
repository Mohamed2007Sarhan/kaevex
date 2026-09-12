import React, { useState } from 'react';
import { AegisLiveData } from '../api/useAegisData';
import { api, APIAlert } from '../api/client';
import { Card } from '../components/UI/Card';
import { Button } from '../components/UI/Button';
import { Shield, AlertTriangle, AlertCircle, XCircle, CheckCircle, Eye, Ban, WifiOff } from 'lucide-react';

interface IntrusionProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
}

const styles = {
  container: { padding: '20px', display: 'flex', flexDirection: 'column' as const, gap: '20px', color: 'hsl(var(--text-primary))' },
  loadingContainer: { display: 'flex', gap: '20px', flexWrap: 'wrap' as const, padding: '20px' },
  skeleton: { backgroundColor: 'hsl(var(--bg-secondary))', height: '100px', flex: '1 1 30%', borderRadius: '8px', animation: 'pulse 1.5s infinite' },
  offlineBanner: { display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: 'hsl(var(--bg-secondary))', padding: '20px', borderRadius: '8px', border: '1px solid red' },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' },
  statCard: { padding: '20px', backgroundColor: 'hsl(var(--bg-secondary))', borderRadius: '8px', display: 'flex', flexDirection: 'column' as const, alignItems: 'center' },
  statValue: { fontSize: '2rem', fontWeight: 'bold', color: 'hsl(var(--accent-color))' },
  statLabel: { fontSize: '0.9rem', opacity: 0.8 },
  filterBar: { display: 'flex', gap: '15px', backgroundColor: 'hsl(var(--bg-secondary))', padding: '15px', borderRadius: '8px', alignItems: 'center' },
  select: { padding: '8px', borderRadius: '4px', backgroundColor: 'hsl(var(--bg-primary))', color: 'hsl(var(--text-primary))', border: '1px solid hsl(var(--accent-color))' },
  badge: { padding: '4px 8px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', color: '#fff' },
  modalOverlay: { position: 'fixed' as const, top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 },
  modalContent: { backgroundColor: 'hsl(var(--bg-secondary))', padding: '20px', borderRadius: '8px', maxWidth: '600px', width: '100%', maxHeight: '80vh', overflowY: 'auto' as const },
  emptyState: { display: 'flex', flexDirection: 'column' as const, alignItems: 'center', padding: '50px', backgroundColor: 'hsl(var(--bg-secondary))', borderRadius: '8px' }
};

export default function Intrusion({ liveData, addToast }: IntrusionProps) {
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [filterEngine, setFilterEngine] = useState('All');
  const [filterBlocked, setFilterBlocked] = useState('All');
  const [page, setPage] = useState(1);
  const [selectedAlert, setSelectedAlert] = useState<APIAlert | null>(null);

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

  const getSeverityColor = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'red';
    if (s === 'high') return 'orange';
    if (s === 'medium') return 'goldenrod';
    return 'gray';
  };

  const handleBanIP = async (ip: string) => {
    try {
      await api.banIP(ip, 3600);
      addToast(`Banned IP ${ip} successfully`, 'success');
    } catch (e) {
      addToast(`Failed to ban IP ${ip}`, 'error');
    }
  };

  const filteredAlerts = liveData.alerts.filter(a => {
    if (filterSeverity !== 'All' && a.severity.toLowerCase() !== filterSeverity.toLowerCase()) return false;
    if (filterEngine !== 'All' && a.engine.toLowerCase() !== filterEngine.toLowerCase()) return false;
    if (filterBlocked !== 'All') {
      const isBlocked = filterBlocked === 'Blocked';
      if (a.blocked !== isBlocked) return false;
    }
    return true;
  });

  const total = liveData.alerts.length;
  const criticalCount = liveData.alerts.filter(a => a.severity.toLowerCase() === 'critical').length;
  const blockedCount = liveData.alerts.filter(a => a.blocked).length;
  const unblockedCount = total - blockedCount;

  const ITEMS_PER_PAGE = 20;
  const totalPages = Math.ceil(filteredAlerts.length / ITEMS_PER_PAGE);
  const paginatedAlerts = filteredAlerts.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);

  return (
    <div style={styles.container}>
      <div style={styles.statsRow}>
        <div style={styles.statCard}>
          <div style={styles.statValue}>{total}</div>
          <div style={styles.statLabel}>Total Alerts</div>
        </div>
        <div style={styles.statCard}>
          <div style={{...styles.statValue, color: 'red'}}>{criticalCount}</div>
          <div style={styles.statLabel}>Critical Alerts</div>
        </div>
        <div style={styles.statCard}>
          <div style={{...styles.statValue, color: 'green'}}>{blockedCount}</div>
          <div style={styles.statLabel}>Blocked</div>
        </div>
        <div style={styles.statCard}>
          <div style={{...styles.statValue, color: 'orange'}}>{unblockedCount}</div>
          <div style={styles.statLabel}>Unblocked</div>
        </div>
      </div>

      <div style={styles.filterBar}>
        <label>Severity:</label>
        <select style={styles.select} value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}>
          <option>All</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>

        <label>Engine:</label>
        <select style={styles.select} value={filterEngine} onChange={e => setFilterEngine(e.target.value)}>
          <option>All</option>
          <option>Suricata</option>
          <option>WebGuard</option>
          <option>AV</option>
          <option>HostGuard</option>
          <option>Nexus</option>
          <option>Sandbox</option>
        </select>

        <label>Status:</label>
        <select style={styles.select} value={filterBlocked} onChange={e => setFilterBlocked(e.target.value)}>
          <option>All</option>
          <option>Blocked</option>
          <option>Active</option>
        </select>
      </div>

      {filteredAlerts.length === 0 ? (
        <div style={styles.emptyState}>
          <Shield size={48} color="hsl(var(--accent-color))" />
          <h3>No alerts detected</h3>
          <p>No intrusion attempts match the current filters.</p>
        </div>
      ) : (
        <Card>
          <div className="table-container"><table className="enterprise-table"><thead>
              <tr>
                <th>Timestamp</th>
                <th>Engine</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Connection</th>
                <th>Protocol</th>
                <th>ATTCK</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.map(alert => (
                <tr key={alert.id}>
                  <td>{new Date(alert.timestamp).toLocaleString()}</td>
                  <td>
                    <span style={{ ...styles.badge, backgroundColor: 'hsl(var(--accent-color))' }}>
                      {alert.engine.toUpperCase()}
                    </span>
                  </td>
                  <td>{alert.type}</td>
                  <td>
                    <span style={{ ...styles.badge, backgroundColor: getSeverityColor(alert.severity) }}>
                      {alert.severity.toUpperCase()}
                    </span>
                  </td>
                  <td>{alert.src_ip}:{alert.src_port} &rarr; {alert.dst_ip}:{alert.dst_port}</td>
                  <td>{alert.proto}</td>
                  <td>{alert.attck || 'N/A'}</td>
                  <td>
                    <span style={{ ...styles.badge, backgroundColor: alert.blocked ? 'green' : 'red' }}>
                      {alert.blocked ? 'BLOCKED' : 'ACTIVE'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '5px' }}>
                      <Button onClick={() => setSelectedAlert(alert)}><Eye size={14} /> View</Button>
                      <Button onClick={() => handleBanIP(alert.src_ip)}><Ban size={14} /> Ban IP</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px' }}>
            <Button disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <span>Page {page} of {totalPages}</span>
            <Button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </Card>
      )}

      {selectedAlert && (
        <div style={styles.modalOverlay} onClick={() => setSelectedAlert(null)}>
          <div style={styles.modalContent} onClick={e => e.stopPropagation()}>
            <h2>Alert Details</h2>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '15px' }}>
              <div><strong>ID:</strong> {selectedAlert.id}</div>
              <div><strong>Engine:</strong> {selectedAlert.engine}</div>
              <div><strong>CWE:</strong> {selectedAlert.cwe || 'N/A'}</div>
              <div><strong>Location:</strong> {selectedAlert.location || 'N/A'}</div>
              <div style={{ gridColumn: '1 / -1' }}><strong>Remediation:</strong> {selectedAlert.remediation || 'N/A'}</div>
              <div style={{ gridColumn: '1 / -1' }}>
                <strong>Payload:</strong>
                <pre style={{ backgroundColor: 'hsl(var(--bg-primary))', padding: '10px', borderRadius: '4px', overflowX: 'auto' }}>
                  {selectedAlert.payload || 'No payload data available.'}
                </pre>
              </div>
            </div>
            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <Button onClick={() => setSelectedAlert(null)}>Close</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
