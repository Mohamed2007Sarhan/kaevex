import React, { useState } from 'react';
import { CheckCircle, XCircle, AlertTriangle, Info } from 'lucide-react';
import { useAegisData } from './api/useAegisData';

// Pages
import Dashboard from './pages/Dashboard';
import { Assets } from './pages/Assets';
import Network from './pages/Network';
import Intrusion from './pages/Intrusion';
import HostSecurity from './pages/HostSecurity';
import ThreatIntel from './pages/ThreatIntel';
import Vulnerabilities from './pages/Vulnerabilities';
import { AIWorkspace } from './pages/AIWorkspace';
import Automation from './pages/Automation';
import Sandbox from './pages/Sandbox';
import Incidents from './pages/Incidents';
import RequestAnalysis from './pages/RequestAnalysis';
import { Reports } from './pages/Reports';
import { AuditLogs } from './pages/AuditLogs';
import { Notifications } from './pages/Notifications';
import UpdateCenter from './pages/UpdateCenter';
import Monitoring from './pages/Monitoring';
import { Organizations } from './pages/Organizations';
import Settings from './pages/Settings';
import Analytics from './pages/Analytics';
import { SearchPage } from './pages/Search';
import Sidebar from './components/Sidebar';
import Header from './components/Header';

export default function App() {
  const liveData = useAegisData();
  const [activePage, setActivePage] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [toasts, setToasts] = useState<{id: string; message: string; type: 'success' | 'info' | 'warning' | 'error'}[]>([]);
  const [auditLogs, setAuditLogs] = useState<{id:string;time:string;user:string;action:string;module:string;ip:string;status:'Success'|'Failed'}[]>([]);

  const addToast = (message: string, type: 'success' | 'info' | 'warning' | 'error') => {
    const id = Date.now().toString();
    setToasts(p => [...p, { id, message, type }]);
    setAuditLogs(p => [{ id: `al-${id}`, time: new Date().toLocaleTimeString(), user: 'Operator', action: message, module: 'AegisCore', ip: '127.0.0.1', status: 'Success' as const }, ...p]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4000);
  };

  const toastIcon = (type: string) => {
    if (type === 'success') return <CheckCircle size={15} color="#22c55e" />;
    if (type === 'error')   return <XCircle size={15} color="#ef4444" />;
    if (type === 'warning') return <AlertTriangle size={15} color="#f59e0b" />;
    return <Info size={15} color="#3b82f6" />;
  };

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':    return <Dashboard liveData={liveData} onNavigate={setActivePage} />;
      case 'assets':       return <Assets liveData={liveData} />;
      case 'network':      return <Network liveData={liveData} />;
      case 'intrusion':    return <Intrusion liveData={liveData} addToast={addToast} />;
      case 'host-security': return <HostSecurity liveData={liveData} addToast={addToast} />;
      case 'threat-intel': return <ThreatIntel liveData={liveData} addToast={addToast} />;
      case 'vulnerabilities': return <Vulnerabilities liveData={liveData} addToast={addToast} />;
      case 'ai-workspace': return <AIWorkspace addToast={addToast} />;
      case 'automation':   return <Automation addToast={addToast} />;
      case 'sandbox':      return <Sandbox liveData={liveData} addToast={addToast} />;
      case 'incidents':    return <Incidents liveData={liveData} addToast={addToast} />;
      case 'request-analysis': return <RequestAnalysis liveData={liveData} addToast={addToast} />;
      case 'reports':      return <Reports liveData={liveData} addToast={addToast} />;
      case 'audit-logs':   return <AuditLogs logs={auditLogs} />;
      case 'notifications': return <Notifications liveData={liveData} addToast={addToast} />;
      case 'update-center': return <UpdateCenter liveData={liveData} addToast={addToast} />;
      case 'monitoring':   return <Monitoring liveData={liveData} addToast={addToast} />;
      case 'organizations': return <Organizations />;
      case 'settings':     return <Settings liveData={liveData} addToast={addToast} />;
      case 'analytics':    return <Analytics liveData={liveData} />;
      case 'search':       return <SearchPage searchQuery={searchQuery} liveData={liveData} onNavigate={setActivePage} />;
      default: return <Dashboard liveData={liveData} onNavigate={setActivePage} />;
    }
  };

  return (
    <div className={`app-container ${darkMode ? 'dark' : 'light'}`}>
      <Sidebar 
        collapsed={sidebarCollapsed} 
        setCollapsed={setSidebarCollapsed} 
        activePage={activePage} 
        setActivePage={setActivePage} 
        connected={liveData?.status?.platform === 'online'} 
      />
      <div className="main-content">
        <Header 
          darkMode={darkMode} 
          setDarkMode={setDarkMode} 
          setSearchQuery={setSearchQuery} 
          onNavigate={setActivePage} 
          liveData={liveData} 
        />
        <div className="page-content">
          {renderPage()}
        </div>
      </div>
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            {toastIcon(toast.type)}
            <span>{toast.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
