/**
 * ConnectionBanner — shows backend status at top of app
 * Green pill when connected, red banner with retry when offline.
 */
import React from 'react';
import { Wifi, WifiOff, RefreshCw, Clock } from 'lucide-react';

interface Props {
  connected: boolean;
  error: string | null;
  lastUpdate: Date | null;
  onRefresh: () => void;
}

export const ConnectionBanner: React.FC<Props> = ({
  connected, error, lastUpdate, onRefresh
}) => {
  if (connected && !error) return null; // fully connected — no banner needed

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      zIndex: 9999,
      background: 'linear-gradient(90deg, #dc2626, #991b1b)',
      color: '#fff',
      padding: '8px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      fontSize: '0.82rem',
      fontWeight: 600,
      boxShadow: '0 2px 12px rgba(220,38,38,0.4)',
    }}>
      <WifiOff size={15} />
      <span>
        AegisCore backend offline — showing cached data.
        {error && <span style={{ opacity: 0.8, marginLeft: 8 }}>({error})</span>}
      </span>
      {lastUpdate && (
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, opacity: 0.75, fontWeight: 400 }}>
          <Clock size={13} />
          Last seen: {lastUpdate.toLocaleTimeString()}
        </span>
      )}
      <button
        onClick={onRefresh}
        style={{
          background: 'rgba(255,255,255,0.15)',
          border: '1px solid rgba(255,255,255,0.3)',
          color: '#fff',
          borderRadius: 6,
          padding: '3px 12px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          fontSize: '0.78rem',
          fontWeight: 600,
        }}
      >
        <RefreshCw size={12} /> Retry
      </button>
    </div>
  );
};

/**
 * LiveBadge — tiny green/red pill showing connection in header
 */
interface BadgeProps {
  connected: boolean;
  lastUpdate: Date | null;
}

export const LiveBadge: React.FC<BadgeProps> = ({ connected, lastUpdate }) => (
  <div style={{
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    padding: '3px 10px',
    borderRadius: 20,
    background: connected ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)',
    border: `1px solid ${connected ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
    fontSize: '0.72rem',
    fontWeight: 700,
    color: connected ? '#22c55e' : '#ef4444',
    userSelect: 'none',
    cursor: 'default',
  }}
  title={lastUpdate ? `Last update: ${lastUpdate.toLocaleTimeString()}` : 'Not connected'}
  >
    <div style={{
      width: 7,
      height: 7,
      borderRadius: '50%',
      background: connected ? '#22c55e' : '#ef4444',
      boxShadow: connected ? '0 0 6px #22c55e' : '0 0 6px #ef4444',
      animation: connected ? 'pulse 2s infinite' : 'none',
    }} />
    {connected ? 'LIVE' : 'OFFLINE'}
  </div>
);
