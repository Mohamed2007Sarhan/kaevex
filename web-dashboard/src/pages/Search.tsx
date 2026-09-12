/**
 * AegisCore — Search Page
 * Search across live backend data.
 * No mock data. No emoji.
 */
import React, { useMemo } from 'react';
import { Search, ShieldAlert, Activity, Eye, ChevronRight } from 'lucide-react';
import { Card } from '../components/UI/Card';
import { AegisLiveData } from '../api/useAegisData';

interface SearchPageProps {
  searchQuery: string;
  liveData: AegisLiveData;
  onNavigate: (page: string) => void;
  // legacy props (ignored)
  assets?: any;
  alerts?: any;
  incidents?: any;
  vulnerabilities?: any;
}

export const SearchPage: React.FC<SearchPageProps> = ({ searchQuery, liveData, onNavigate }) => {
  const q = searchQuery.trim().toLowerCase();

  const results = useMemo(() => {
    if (!q) return { alerts: [], incidents: [], ioc: [], sessions: [] };

    return {
      alerts: liveData.alerts.filter(a =>
        a.type?.toLowerCase().includes(q) ||
        a.src_ip?.includes(q) ||
        a.dst_ip?.includes(q) ||
        a.engine?.toLowerCase().includes(q) ||
        a.payload?.toLowerCase().includes(q) ||
        a.attck?.toLowerCase().includes(q)
      ).slice(0, 10),

      incidents: liveData.incidents.filter(i =>
        i.title?.toLowerCase().includes(q) ||
        i.attacker_ip?.includes(q) ||
        i.target_ip?.includes(q) ||
        i.threat_family?.toLowerCase().includes(q) ||
        i.techniques?.toLowerCase().includes(q)
      ).slice(0, 10),

      ioc: liveData.ioc.filter(i =>
        i.value?.toLowerCase().includes(q) ||
        i.type?.toLowerCase().includes(q) ||
        i.threat_actor?.toLowerCase().includes(q) ||
        i.campaign?.toLowerCase().includes(q)
      ).slice(0, 10),

      sessions: liveData.sessions.filter(s =>
        s.attacker_ip?.includes(q) ||
        s.target_ip?.includes(q) ||
        s.threat_family?.toLowerCase().includes(q)
      ).slice(0, 5),
    };
  }, [q, liveData]);

  const total = results.alerts.length + results.incidents.length + results.ioc.length + results.sessions.length;

  if (!q) {
    return (
      <div className="page-container animate-fade-in" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, gap: 12, color: 'hsl(var(--text-secondary))' }}>
        <Search size={40} opacity={0.3} />
        <p style={{ fontSize: '0.9rem' }}>Type in the search box to search across alerts, incidents, IOCs, and sessions.</p>
      </div>
    );
  }

  return (
    <div className="page-container animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '1.5rem' }}>
        <Search size={18} style={{ color: 'hsl(var(--accent-color))' }} />
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Search: "{searchQuery}"</h2>
        <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>{total} results</span>
      </div>

      {total === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'hsl(var(--text-secondary))' }}>
          <Search size={40} opacity={0.2} style={{ display: 'block', margin: '0 auto 12px' }} />
          <p>No results found for "{searchQuery}"</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Alerts */}
          {results.alerts.length > 0 && (
            <Card>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem', cursor: 'pointer' }} onClick={() => onNavigate('intrusion')}>
                <ShieldAlert size={16} style={{ color: '#ef4444' }} />
                <span style={{ fontWeight: 700 }}>Alerts ({results.alerts.length})</span>
                <ChevronRight size={14} style={{ marginLeft: 'auto', color: 'hsl(var(--text-secondary))' }} />
              </div>
              {results.alerts.map(a => (
                <div key={a.id} style={{ padding: '8px 0', borderBottom: '1px solid hsl(var(--border-primary))', display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span style={{ padding: '2px 6px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 700, background: a.severity === 'critical' ? '#ef444422' : '#f9731622', color: a.severity === 'critical' ? '#ef4444' : '#f97316' }}>
                    {a.severity.toUpperCase()}
                  </span>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>[{a.engine}] {a.type}</div>
                    <div style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{a.src_ip} — {new Date(a.timestamp).toLocaleString()}</div>
                  </div>
                </div>
              ))}
            </Card>
          )}

          {/* Incidents */}
          {results.incidents.length > 0 && (
            <Card>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem', cursor: 'pointer' }} onClick={() => onNavigate('incidents')}>
                <Activity size={16} style={{ color: '#f97316' }} />
                <span style={{ fontWeight: 700 }}>Incidents ({results.incidents.length})</span>
                <ChevronRight size={14} style={{ marginLeft: 'auto', color: 'hsl(var(--text-secondary))' }} />
              </div>
              {results.incidents.map(i => (
                <div key={i.incident_id} style={{ padding: '8px 0', borderBottom: '1px solid hsl(var(--border-primary))' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>{i.title}</div>
                  <div style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{i.attacker_ip} — Score: {i.threat_score} — {i.threat_family}</div>
                </div>
              ))}
            </Card>
          )}

          {/* IOC */}
          {results.ioc.length > 0 && (
            <Card>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem', cursor: 'pointer' }} onClick={() => onNavigate('threat-intel')}>
                <Eye size={16} style={{ color: '#8b5cf6' }} />
                <span style={{ fontWeight: 700 }}>Threat Intel IOCs ({results.ioc.length})</span>
                <ChevronRight size={14} style={{ marginLeft: 'auto', color: 'hsl(var(--text-secondary))' }} />
              </div>
              {results.ioc.map((i, idx) => (
                <div key={idx} style={{ padding: '8px 0', borderBottom: '1px solid hsl(var(--border-primary))', display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span style={{ padding: '2px 6px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 600, background: 'hsl(var(--accent-color) / 0.1)', color: 'hsl(var(--accent-color))' }}>{i.type}</span>
                  <div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', fontWeight: 600 }}>{i.value}</div>
                    <div style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{i.threat_actor} — {i.campaign} — Hits: {i.hit_count}</div>
                  </div>
                </div>
              ))}
            </Card>
          )}
        </div>
      )}
    </div>
  );
};
