import React from 'react';
import { 
  Home, Server, Activity, Shield, Cpu, Target, AlertCircle, Bot, Zap,
  Box, FileText, Search, Settings, ShieldAlert, Book, Briefcase, Eye, Map, PieChart
} from 'lucide-react';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (c: boolean) => void;
  activePage: string;
  setActivePage: (p: string) => void;
  connected?: boolean;
}

const ShieldLogo = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z" 
          fill="hsl(var(--accent-color))" opacity="0.9"/>
    <path d="M9 12l2 2 4-4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

export default function Sidebar({ collapsed, setCollapsed, activePage, setActivePage, connected }: SidebarProps) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <Home size={18} /> },
    { id: 'assets', label: 'Assets', icon: <Server size={18} /> },
    { id: 'network', label: 'Network', icon: <Activity size={18} /> },
    { id: 'intrusion', label: 'Intrusion', icon: <ShieldAlert size={18} /> },
    { id: 'host-security', label: 'Host Security', icon: <Cpu size={18} /> },
    { id: 'threat-intel', label: 'Threat Intel', icon: <Target size={18} /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <AlertCircle size={18} /> },
    { id: 'ai-workspace', label: 'AI Agent Center', icon: <Bot size={18} />, isAgent: true },
    { id: 'automation', label: 'Automation', icon: <Zap size={18} /> },
    { id: 'sandbox', label: 'Sandbox', icon: <Box size={18} /> },
    { id: 'incidents', label: 'Incidents', icon: <FileText size={18} /> },
    { id: 'request-analysis', label: 'Request Analysis', icon: <Search size={18} /> },
    { id: 'reports', label: 'Reports', icon: <Book size={18} /> },
    { id: 'audit-logs', label: 'Audit Logs', icon: <FileText size={18} /> },
    { id: 'notifications', label: 'Notifications', icon: <AlertCircle size={18} /> },
    { id: 'update-center', label: 'Update Center', icon: <Server size={18} /> },
    { id: 'monitoring', label: 'Monitoring', icon: <Eye size={18} /> },
    { id: 'organizations', label: 'Organizations', icon: <Briefcase size={18} /> },
    { id: 'analytics', label: 'Analytics', icon: <PieChart size={18} /> },
    { id: 'settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : 'expanded'}`}>
      <div className="sidebar-header" onClick={() => setCollapsed(!collapsed)} style={{ cursor: 'pointer' }}>
        <div className="logo-container" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldLogo />
          {!collapsed && <span style={{ fontWeight: 'bold', letterSpacing: '1px' }}>AEGISCORE</span>}
          {!collapsed && (
             <div style={{ 
               width: 8, height: 8, borderRadius: '50%', 
               backgroundColor: connected ? '#22c55e' : '#ef4444', 
               marginLeft: 'auto' 
             }} />
          )}
        </div>
      </div>
      <div className="sidebar-menu">
        {menuItems.map(item => (
          <div 
            key={item.id} 
            className={`sidebar-item ${activePage === item.id ? 'active' : ''}`}
            onClick={() => setActivePage(item.id)}
          >
            {item.icon}
            {!collapsed && (
              item.isAgent ? (
                <span style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                  {item.label}
                  <span style={{marginLeft:'auto',fontSize:'0.6rem',color:'hsl(var(--text-secondary))',fontWeight:600,letterSpacing:'0.05em'}}>SOON</span>
                </span>
              ) : (
                <span>{item.label}</span>
              )
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
