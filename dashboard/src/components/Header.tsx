import React from 'react';
import { Shield, Search, Moon, Sun, Bell } from 'lucide-react';

interface HeaderProps {
  darkMode: boolean;
  setDarkMode: (d: boolean) => void;
  setSearchQuery: (q: string) => void;
  onNavigate: (p: string) => void;
  liveData: any;
}

export default function Header({ darkMode, setDarkMode, setSearchQuery, onNavigate, liveData }: HeaderProps) {
  const requests = liveData?.stats?.api?.requests_served || 0;
  const lastUpdate = liveData?.lastUpdate ? new Date(liveData.lastUpdate).toLocaleTimeString() : 'Unknown';

  return (
    <div className="header">
      <div className="header-left">
        <div className="breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={18} />
          <span>AegisCore Platform</span>
        </div>
      </div>
      <div className="header-center">
        <div className="search-bar">
          <Search size={16} />
          <input 
            type="text" 
            placeholder="Search commands, data..." 
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') onNavigate('search');
            }}
          />
        </div>
      </div>
      <div className="header-right" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div className="stats-badge" style={{ fontSize: '0.8rem', color: '#666' }}>
          API Req: {requests}
        </div>
        <div className="stats-badge" style={{ fontSize: '0.8rem', color: '#666' }}>
          Updated: {lastUpdate}
        </div>
        <button onClick={() => setDarkMode(!darkMode)} className="icon-button">
          {darkMode ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button onClick={() => onNavigate('notifications')} className="icon-button">
          <Bell size={18} />
        </button>
      </div>
    </div>
  );
}
