import React, { useState } from 'react';
import { Settings as SettingsIcon, Shield, Cpu, RefreshCw, Save, ToggleLeft, ToggleRight } from 'lucide-react';
import { api } from '../api/client';
import { AegisLiveData } from '../api/useAegisData';

interface SettingsProps {
  liveData: AegisLiveData;
  addToast: (msg: string, type: 'success'|'info'|'warning'|'error') => void;
}

export default function Settings({ liveData, addToast }: SettingsProps) {
  const [activeTab, setActiveTab] = useState('system');
  const [port, setPort] = useState(3000);
  const [backendUrl, setBackendUrl] = useState('http://127.0.0.1:9009');
  const [autoStart, setAutoStart] = useState(false);
  const [trayEnabled, setTrayEnabled] = useState(true);

  const handleSaveSystem = () => {
    localStorage.setItem('aegis_port', port.toString());
    localStorage.setItem('aegis_backend_url', backendUrl);
    localStorage.setItem('aegis_autostart', autoStart.toString());
    localStorage.setItem('aegis_tray', trayEnabled.toString());
    fetch('/api/v1/system/autostart', { method: 'POST', body: JSON.stringify({ autoStart }) }).catch(() => {});
    addToast('System settings saved', 'success');
  };

  const handleSetWafProfile = async (profile: string) => {
    try {
      if (api.wafSetProfile) await api.wafSetProfile(profile);
      addToast(`WAF profile set to ${profile}`, 'success');
    } catch (e) {
      addToast('Failed to set WAF profile', 'error');
    }
  };

  const triggerFullScan = async () => {
    try {
      if (api.avFullScan) await api.avFullScan();
      addToast('AV Full Scan initiated', 'info');
    } catch (e) {
      addToast('Failed to start AV scan', 'error');
    }
  };

  const triggerHostRescan = async () => {
    try {
      if (api.hostguardForceScan) await api.hostguardForceScan();
      addToast('HostGuard rescan initiated', 'info');
    } catch (e) {
      addToast('Failed to start HostGuard rescan', 'error');
    }
  };

  return (
    <div className="settings-page" style={{ padding: 20 }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <SettingsIcon size={24} /> Settings
      </h2>
      
      <div className="tabs" style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        {['system', 'waf', 'av', 'host', 'platform'].map(t => (
          <button 
            key={t}
            onClick={() => setActiveTab(t)}
            style={{ fontWeight: activeTab === t ? 'bold' : 'normal', padding: '8px 16px', cursor: 'pointer', border: '1px solid #ccc', background: 'transparent' }}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="tab-content">
        {activeTab === 'system' && (
          <div className="section">
            <h3>System & Tray</h3>
            <div style={{ marginBottom: 15 }}>
              <label>Dashboard Port: </label>
              <input type="number" value={port} onChange={e => setPort(Number(e.target.value))} />
            </div>
            <div style={{ marginBottom: 15 }}>
              <label>Backend API URL: </label>
              <input type="text" value={backendUrl} onChange={e => setBackendUrl(e.target.value)} />
            </div>
            <div style={{ marginBottom: 15, display: 'flex', alignItems: 'center', gap: 10 }}>
              <label>Auto-Start with Windows: </label>
              <button onClick={() => setAutoStart(!autoStart)} style={{ border: 'none', background: 'transparent', cursor: 'pointer' }}>
                {autoStart ? <ToggleRight size={24} color="#22c55e" /> : <ToggleLeft size={24} />}
              </button>
            </div>
            <div style={{ marginBottom: 15, display: 'flex', alignItems: 'center', gap: 10 }}>
              <label>Tray Icon: </label>
              <button onClick={() => setTrayEnabled(!trayEnabled)} style={{ border: 'none', background: 'transparent', cursor: 'pointer' }}>
                {trayEnabled ? <ToggleRight size={24} color="#22c55e" /> : <ToggleLeft size={24} />}
              </button>
            </div>
            <button onClick={handleSaveSystem} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '8px 16px', cursor: 'pointer' }}>
              <Save size={16} /> Save Settings
            </button>
          </div>
        )}

        {activeTab === 'waf' && (
          <div className="section">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Shield size={20} /> WebGuard WAF</h3>
            <p>Current Profile: {liveData.stats?.webguard?.profile || 'Moderate'}</p>
            <div style={{ marginBottom: 15 }}>
              <label>Set Profile: </label>
              <select onChange={e => handleSetWafProfile(e.target.value)} defaultValue="">
                <option value="" disabled>--Select--</option>
                <option value="Transparent">Transparent</option>
                <option value="Moderate">Moderate</option>
                <option value="Aggressive">Aggressive</option>
                <option value="Paranoid">Paranoid</option>
              </select>
            </div>
            <p>Block Threshold: {liveData.stats?.webguard?.block_threshold || 'N/A'}</p>
            <p>Rate Limit: {liveData.stats?.webguard?.rate_limit_rps || 'N/A'} RPS</p>
            <p>Allowlist Count: {liveData.stats?.webguard?.allowlist_count || '0'}</p>
          </div>
        )}

        {activeTab === 'av' && (
          <div className="section">
            <h3>AV Engine</h3>
            <p>Realtime Enabled: {liveData.stats?.av?.realtime_enabled ? 'Yes' : 'No'}</p>
            <p>Auto Kill: {liveData.stats?.av?.auto_kill ? 'Yes' : 'No'}</p>
            <p>Memory Scan: {liveData.stats?.av?.memory_scan_enabled ? 'Yes' : 'No'}</p>
            <p>Hash DB Size: {(liveData.stats?.av?.hash_db_size || 0).toLocaleString()}</p>
            <p>Pattern Count: {liveData.stats?.av?.pattern_count || 0}</p>
            <button onClick={triggerFullScan} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '8px 16px', cursor: 'pointer' }}>
              <Shield size={16} /> Trigger Full Scan
            </button>
          </div>
        )}

        {activeTab === 'host' && (
          <div className="section">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Cpu size={20} /> HostGuard</h3>
            <p>Thread Count: {liveData.stats?.hostguard?.thread_count || 0}</p>
            <p>Honeypot Count: {liveData.stats?.hostguard?.honeypot_count || 0}</p>
            <p>Ransomware Lockdown: {liveData.stats?.hostguard?.ransomware_lockdown || 'Disabled'}</p>
            <button onClick={triggerHostRescan} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '8px 16px', cursor: 'pointer' }}>
              <RefreshCw size={16} /> Force Rescan
            </button>
          </div>
        )}

        {activeTab === 'platform' && (
          <div className="section">
            <h3>Platform Info</h3>
            <p>Status: {liveData.status?.platform || 'Unknown'}</p>
            <p>Version: {liveData.status?.version || 'N/A'}</p>
            <p>API Version: {liveData.status?.api_version || 'N/A'}</p>
            <p>Uptime: {liveData.status?.uptime_seconds || 'N/A'}</p>
            <p>Requests Served: {liveData.stats?.api?.requests_served || 0}</p>
            <button 
              onClick={() => {
                if (liveData.refresh) liveData.refresh();
                addToast("Data refreshed", 'success');
              }} 
              style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '8px 16px', cursor: 'pointer' }}
            >
              <RefreshCw size={16} /> Refresh Info
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
