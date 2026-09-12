import React, { useState, useEffect, useRef } from 'react';
import { Search, Monitor, Shield, Play, Command, FileText, Settings, User } from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (page: string) => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Command database
  const commands = [
    // Navigation
    { id: 'dashboard', category: 'Navigation', title: 'Go to Executive Dashboard', subtitle: 'View security score and platform health', icon: Command, action: () => onNavigate('dashboard') },
    { id: 'assets', category: 'Navigation', title: 'Go to Asset Management', subtitle: 'View servers and endpoints inventory', icon: Monitor, action: () => onNavigate('assets') },
    { id: 'network', category: 'Navigation', title: 'Go to Network Visibility', subtitle: 'View live traffic maps and protocol stats', icon: Shield, action: () => onNavigate('network') },
    { id: 'intrusion', category: 'Navigation', title: 'Go to Intrusion Detection', subtitle: 'Check Suricata alerts and detection rules', icon: Shield, action: () => onNavigate('intrusion') },
    { id: 'host-security', category: 'Navigation', title: 'Go to Host Security', subtitle: 'Check Wazuh FIM logs and system processes', icon: Monitor, action: () => onNavigate('host-security') },
    { id: 'threat-intel', category: 'Navigation', title: 'Go to Threat Intelligence', subtitle: 'Inspect Indicators of Compromise (IOCs)', icon: Search, action: () => onNavigate('threat-intel') },
    { id: 'vulnerabilities', category: 'Navigation', title: 'Go to CVE & Intel Center', subtitle: 'Review risk rating and CVE database', icon: Search, action: () => onNavigate('vulnerabilities') },
    { id: 'ai-workspace', category: 'Navigation', title: 'Go to AI Agent Center', subtitle: 'Manage autonomous security agents and logs', icon: User, action: () => onNavigate('ai-workspace') },
    { id: 'automation', category: 'Navigation', title: 'Go to Security Automation', subtitle: 'Review detection and response pipelines', icon: Play, action: () => onNavigate('automation') },
    { id: 'sandbox', category: 'Navigation', title: 'Go to Smart Sandbox Center', subtitle: 'Submit apps and inspect execution graphs', icon: Play, action: () => onNavigate('sandbox') },
    { id: 'incidents', category: 'Navigation', title: 'Go to Incident Management', subtitle: 'View incident logs and analyst responses', icon: Shield, action: () => onNavigate('incidents') },
    { id: 'request-analysis', category: 'Navigation', title: 'Go to Request Analysis Center', subtitle: 'Inspect raw HTTP logs and risk assessments', icon: Shield, action: () => onNavigate('request-analysis') },
    { id: 'reports', category: 'Navigation', title: 'Go to Reports Designer', subtitle: 'Generate PDF or CSV compliance reports', icon: FileText, action: () => onNavigate('reports') },
    { id: 'settings', category: 'System', title: 'Go to Settings', subtitle: 'Update preferences, API keys, and integrations', icon: Settings, action: () => onNavigate('settings') },
    
    // Quick Actions
    { id: 'scan-sandbox', category: 'Quick Actions', title: 'Sandbox: Submit new file', subtitle: 'Upload executable for immediate emulation', icon: Play, action: () => { onNavigate('sandbox'); } },
    { id: 'audit-requests', category: 'Quick Actions', title: 'Request Analysis: Audit logs', subtitle: 'Filter suspicious web queries in real-time', icon: Search, action: () => { onNavigate('request-analysis'); } },
    { id: 'clear-alerts', category: 'Quick Actions', title: 'Threat Intel: Check Reputation', subtitle: 'Verify IP/Domain threat status in real-time', icon: Search, action: () => { onNavigate('threat-intel'); } }
  ];

  // Filter commands based on query
  const filtered = commands.filter(cmd =>
    cmd.title.toLowerCase().includes(query.toLowerCase()) ||
    cmd.subtitle.toLowerCase().includes(query.toLowerCase()) ||
    cmd.category.toLowerCase().includes(query.toLowerCase())
  );

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Handle keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => (prev + 1) % Math.max(filtered.length, 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => (prev - 1 + filtered.length) % Math.max(filtered.length, 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          filtered[selectedIndex].action();
          onClose();
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filtered, selectedIndex, onClose]);

  if (!isOpen) return null;

  // Group by category for visual sections
  const categories: { [key: string]: typeof filtered } = {};
  filtered.forEach(cmd => {
    if (!categories[cmd.category]) {
      categories[cmd.category] = [];
    }
    categories[cmd.category].push(cmd);
  });

  let globalIndex = 0;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="command-palette" onClick={e => e.stopPropagation()}>
        <div className="command-input-container">
          <Search size={18} style={{ color: 'hsl(var(--text-secondary))' }} />
          <input
            ref={inputRef}
            type="text"
            className="command-input"
            placeholder="Type a command or search..."
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
          />
        </div>

        <div className="command-list">
          {filtered.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'hsl(var(--text-secondary))', fontSize: '0.875rem' }}>
              No results found for "{query}"
            </div>
          ) : (
            Object.keys(categories).map(catName => (
              <div key={catName}>
                <div className="command-group-label">{catName}</div>
                {categories[catName].map(cmd => {
                  const Icon = cmd.icon;
                  const currentIndex = globalIndex++;
                  const isSelected = currentIndex === selectedIndex;
                  return (
                    <div
                      key={cmd.id}
                      className={`command-item ${isSelected ? 'selected' : ''}`}
                      onClick={() => {
                        cmd.action();
                        onClose();
                      }}
                      onMouseEnter={() => setSelectedIndex(currentIndex)}
                    >
                      <div style={{
                        backgroundColor: isSelected ? 'hsl(var(--accent-light))' : 'hsl(var(--bg-tertiary))',
                        color: isSelected ? 'hsl(var(--accent-color))' : 'hsl(var(--text-secondary))',
                        padding: '6px',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        transition: 'all 0.15s ease'
                      }}>
                        <Icon size={14} />
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: 600, color: 'hsl(var(--text-primary))', fontSize: '0.85rem' }}>
                          {cmd.title}
                        </span>
                        <span style={{ color: 'hsl(var(--text-secondary))', fontSize: '0.75rem' }}>
                          {cmd.subtitle}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>
        <div style={{ padding: '0.5rem 1rem', borderTop: '1px solid hsl(var(--border-primary))', fontSize: '0.7rem', color: 'hsl(var(--text-secondary))', display: 'flex', gap: '1rem' }}>
          <span>↑↓ to navigate</span>
          <span>↵ to select</span>
          <span>esc to close</span>
        </div>
      </div>
    </div>
  );
};
