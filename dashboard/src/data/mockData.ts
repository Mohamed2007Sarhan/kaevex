// Mock Data Service for Aegis Autonomous Security Platform

export interface Asset {
  id: string;
  name: string;
  type: 'Server' | 'Endpoint';
  os: string;
  ip: string;
  status: 'Online' | 'Offline' | 'Critical';
  cpu: number;
  memory: number;
  servicesCount: number;
  appsCount: number;
  interfaces: string[];
  tags: string[];
  group: string;
  services: string[];
  applications: { name: string; version: string }[];
}

export interface NetworkSession {
  id: string;
  time: string;
  source: string;
  destination: string;
  protocol: 'DNS' | 'HTTP' | 'HTTPS' | 'SSH' | 'SMB';
  bytes: number;
  info: string;
  status: 'Allowed' | 'Blocked' | 'Flagged';
}

export interface IntrusionAlert {
  id: string;
  time: string;
  ruleId: string;
  ruleName: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  source: string;
  destination: string;
  payload: string;
  status: 'Active' | 'Dismissed' | 'Escalated';
}

export interface HostEvent {
  id: string;
  time: string;
  type: 'FIM' | 'Login' | 'Process' | 'Config' | 'Health';
  assetName: string;
  message: string;
  user?: string;
  details: string;
  severity: 'Info' | 'Warning' | 'Error';
}

export interface ThreatIntelIOC {
  id: string;
  type: 'IP' | 'Domain' | 'Hash' | 'URL';
  value: string;
  reputation: 'Malicious' | 'Suspicious' | 'Clean';
  score: number;
  feed: string;
  published: string;
}

export interface Vulnerability {
  id: string;
  cve: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss: number;
  affectedAssets: string[];
  mitigation: string;
  advisory: string;
  status: 'Open' | 'Mitigated' | 'Patched';
}

export interface AIAgent {
  id: string;
  name: string;
  role: string;
  status: 'Idle' | 'Active' | 'Thinking' | 'Error';
  health: 'Healthy' | 'Degraded';
  permissions: string[];
  activity: string;
  reasoning: string[];
}

export interface AutomationWorkflow {
  id: string;
  name: string;
  type: 'Detection' | 'Analysis' | 'Response';
  status: 'Active' | 'Inactive';
  steps: string[];
  lastRun: string;
  successRate: number;
}

export interface SandboxSession {
  id: string;
  filename: string;
  hash: string;
  status: 'Completed' | 'Analyzing' | 'Pending';
  score: number; // 0-100
  time: string;
  behavior: string[];
  filesCreated: string[];
  registryKeys: string[];
  networkCalls: string[];
}

export interface Incident {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Open' | 'Investigating' | 'Resolved';
  assignedTo: string;
  openedAt: string;
  timeline: { time: string; event: string }[];
  evidence: string[];
  comments: { user: string; time: string; text: string }[];
  eventsCount: number;
}

export interface AuditLog {
  id: string;
  time: string;
  user: string;
  action: string;
  module: string;
  ip: string;
  status: 'Success' | 'Failed';
}

// Initial Data Population
export const mockAssets: Asset[] = [
  {
    id: '1',
    name: 'db-prod-01',
    type: 'Server',
    os: 'Ubuntu 22.04 LTS',
    ip: '10.0.4.15',
    status: 'Online',
    cpu: 28,
    memory: 64,
    servicesCount: 12,
    appsCount: 18,
    interfaces: ['eth0 (10.0.4.15)', 'lo (127.0.0.1)'],
    tags: ['Database', 'Production', 'PCI-DSS'],
    group: 'Core Databases',
    services: ['postgresql.service', 'sshd.service', 'node-exporter.service', 'docker.service'],
    applications: [
      { name: 'PostgreSQL', version: '15.2' },
      { name: 'Docker', version: '24.0.2' },
      { name: 'OpenSSH', version: '8.9p1' }
    ]
  },
  {
    id: '2',
    name: 'app-web-01',
    type: 'Server',
    os: 'Red Hat Enterprise Linux 9',
    ip: '10.0.2.10',
    status: 'Critical',
    cpu: 94,
    memory: 82,
    servicesCount: 9,
    appsCount: 22,
    interfaces: ['eth0 (10.0.2.10)', 'eth1 (192.168.1.1)'],
    tags: ['Web Frontend', 'Production', 'DMZ'],
    group: 'Web Tier',
    services: ['nginx.service', 'node-app.service', 'sshd.service'],
    applications: [
      { name: 'Nginx', version: '1.24.0' },
      { name: 'Node.js', version: '18.16.0' },
      { name: 'OpenSSL', version: '3.0.7' }
    ]
  },
  {
    id: '3',
    name: 'auth-ldap-02',
    type: 'Server',
    os: 'Debian 11',
    ip: '10.0.3.5',
    status: 'Online',
    cpu: 12,
    memory: 45,
    servicesCount: 6,
    appsCount: 10,
    interfaces: ['eth0 (10.0.3.5)'],
    tags: ['Identity', 'Internal', 'Critical'],
    group: 'Identity Access',
    services: ['slapd.service', 'sshd.service'],
    applications: [
      { name: 'OpenLDAP', version: '2.5.13' },
      { name: 'OpenSSH', version: '8.4p1' }
    ]
  },
  {
    id: '4',
    name: 'usr-win-104',
    type: 'Endpoint',
    os: 'Windows 11 Enterprise',
    ip: '10.0.10.104',
    status: 'Online',
    cpu: 45,
    memory: 58,
    servicesCount: 145,
    appsCount: 52,
    interfaces: ['Wi-Fi (10.0.10.104)', 'Bluetooth'],
    tags: ['HR Department', 'Workstation'],
    group: 'Employee Endpoints',
    services: ['WinRM', 'wuauserv', 'WazuhSvc', 'CrowdstrikeFalcon'],
    applications: [
      { name: 'Office 365', version: '16.0' },
      { name: 'Slack', version: '4.32.12' },
      { name: 'Chrome', version: '121.0' }
    ]
  },
  {
    id: '5',
    name: 'usr-mac-220',
    type: 'Endpoint',
    os: 'macOS Sonoma 14.1',
    ip: '10.0.10.220',
    status: 'Online',
    cpu: 18,
    memory: 70,
    servicesCount: 98,
    appsCount: 41,
    interfaces: ['en0 (10.0.10.220)'],
    tags: ['Engineering', 'Laptop'],
    group: 'Employee Endpoints',
    services: ['sshd', 'WazuhSvc', 'Falcon'],
    applications: [
      { name: 'VS Code', version: '1.85' },
      { name: 'Docker Desktop', version: '4.25' },
      { name: 'Zoom', version: '5.16' }
    ]
  }
];

export const mockNetworkSessions: NetworkSession[] = [
  {
    id: 'ns-1',
    time: '23:04:12',
    source: '10.0.10.104',
    destination: '185.190.140.52',
    protocol: 'HTTPS',
    bytes: 42104,
    info: 'TLSv1.3 Handshake completed. Sni: slack.com',
    status: 'Allowed'
  },
  {
    id: 'ns-2',
    time: '23:04:45',
    source: '10.0.2.10',
    destination: '8.8.8.8',
    protocol: 'DNS',
    bytes: 84,
    info: 'Query: TXT update.api.threatfeed.io',
    status: 'Flagged'
  },
  {
    id: 'ns-3',
    time: '23:05:01',
    source: '198.51.100.42',
    destination: '10.0.2.10',
    protocol: 'SSH',
    bytes: 3120,
    info: 'Failed authentication for root. Cipher: chacha20',
    status: 'Blocked'
  },
  {
    id: 'ns-4',
    time: '23:05:03',
    source: '10.0.4.15',
    destination: '10.0.3.5',
    protocol: 'SMB',
    bytes: 874020,
    info: 'IPC$ Connection. File Read: \\\\auth-ldap-02\\sysvol\\schema.json',
    status: 'Allowed'
  },
  {
    id: 'ns-5',
    time: '23:05:09',
    source: '10.0.10.220',
    destination: '142.250.74.46',
    protocol: 'HTTP',
    bytes: 1205,
    info: 'GET /index.html. Host: dev-internal.net',
    status: 'Allowed'
  }
];

export const mockIntrusionAlerts: IntrusionAlert[] = [
  {
    id: 'al-1',
    time: '2026-07-16 23:01:10',
    ruleId: '2019842',
    ruleName: 'ET SCAN Potential SSH Brute Force Attempt',
    severity: 'High',
    source: '198.51.100.42',
    destination: '10.0.2.10',
    payload: '00 04 2f 1a db a1 f3 c4 ... [SSH-2.0-OpenSSH_8.9]',
    status: 'Active'
  },
  {
    id: 'al-2',
    time: '2026-07-16 22:45:18',
    ruleId: '2034901',
    ruleName: 'ET MALWARE Possible Reverse Shell Active Connection',
    severity: 'Critical',
    source: '10.0.2.10',
    destination: '45.89.200.12',
    payload: '69 64 0a 75 69 64 3d 30 28 72 6f 6f 74 29 ... [id\\nuid=0(root)]',
    status: 'Active'
  },
  {
    id: 'al-3',
    time: '2026-07-16 21:12:05',
    ruleId: '2024831',
    ruleName: 'ET EXPLOIT Log4j RCE CVE-2021-44228 Attempt',
    severity: 'Critical',
    source: '185.220.101.4',
    destination: '10.0.2.10',
    payload: '24 7b 6a 6e 64 69 3a 6c 64 61 70 3a 2f 2f ... [${jndi:ldap://...}]',
    status: 'Escalated'
  },
  {
    id: 'al-4',
    time: '2026-07-16 20:30:11',
    ruleId: '2001844',
    ruleName: 'ET POLICY Cleartext Password Sent over HTTP',
    severity: 'Medium',
    source: '10.0.10.104',
    destination: '192.168.10.45',
    payload: '75 73 65 72 3d 61 64 6d 69 6e 26 70 61 73 73 ... [user=admin&pass=...]',
    status: 'Dismissed'
  }
];

export const mockHostEvents: HostEvent[] = [
  {
    id: 'he-1',
    time: '23:03:00',
    type: 'FIM',
    assetName: 'app-web-01',
    message: 'File modified in system binary directory: /usr/sbin/nginx',
    user: 'unknown',
    details: 'MD5 changed from a5c1e95e1e07b8b2ba... to c49b06822fe1a8f902...',
    severity: 'Error'
  },
  {
    id: 'he-2',
    time: '23:02:15',
    type: 'Login',
    assetName: 'db-prod-01',
    message: 'Successful login for admin via SSH from 10.0.10.220',
    user: 'admin',
    details: 'SSH session established using RSA key SHA256:d8a2... root login disabled.',
    severity: 'Info'
  },
  {
    id: 'he-3',
    time: '22:58:12',
    type: 'Process',
    assetName: 'usr-win-104',
    message: 'Unsigned executable spawned from Temp folder: temp_install.exe',
    user: 'jdoe',
    details: 'PID: 8402, Parent: cmd.exe, SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    severity: 'Warning'
  },
  {
    id: 'he-4',
    time: '22:40:00',
    type: 'Config',
    assetName: 'auth-ldap-02',
    message: 'LDAP Schema access controls updated',
    user: 'system',
    details: 'Schema write permission added for group Admin-API',
    severity: 'Warning'
  }
];

export const mockIOCs: ThreatIntelIOC[] = [
  {
    id: 'ioc-1',
    type: 'IP',
    value: '45.89.200.12',
    reputation: 'Malicious',
    score: 98,
    feed: 'AlienVault OTX',
    published: '2026-07-16'
  },
  {
    id: 'ioc-2',
    type: 'Domain',
    value: 'update.api.threatfeed.io',
    reputation: 'Suspicious',
    score: 65,
    feed: 'Abuse.ch URLhaus',
    published: '2026-07-15'
  },
  {
    id: 'ioc-3',
    type: 'Hash',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    reputation: 'Malicious',
    score: 100,
    feed: 'VirusTotal',
    published: '2026-07-14'
  },
  {
    id: 'ioc-4',
    type: 'URL',
    value: 'http://dev-internal.net/malicious_payload.sh',
    reputation: 'Malicious',
    score: 95,
    feed: 'Emerging Threats',
    published: '2026-07-16'
  }
];

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'vul-1',
    cve: 'CVE-2024-3094',
    title: 'XZ Utils Backdoor Remote Code Execution',
    severity: 'Critical',
    cvss: 10.0,
    affectedAssets: ['db-prod-01', 'app-web-01'],
    mitigation: 'Downgrade XZ Utils package to 5.4.6 or apply security patch immediately.',
    advisory: 'US-CERT TA24-091A',
    status: 'Open'
  },
  {
    id: 'vul-2',
    cve: 'CVE-2023-38606',
    title: 'Apple macOS Kernel Memory Corruption (Zero-day)',
    severity: 'High',
    cvss: 7.8,
    affectedAssets: ['usr-mac-220'],
    mitigation: 'Update macOS to version 14.1 or apply standalone Apple patch.',
    advisory: 'HT213841',
    status: 'Patched'
  },
  {
    id: 'vul-3',
    cve: 'CVE-2023-4863',
    title: 'libwebp Heap Buffer Overflow Vulnerability',
    severity: 'High',
    cvss: 8.8,
    affectedAssets: ['usr-win-104', 'usr-mac-220', 'db-prod-01'],
    mitigation: 'Rebuild applications using patched libwebp library or update Google Chrome/Slack clients.',
    advisory: 'CVE-2023-4863 Advisory',
    status: 'Mitigated'
  }
];

export const mockAgents: AIAgent[] = [
  {
    id: 'ag-1',
    name: 'Triage Agent',
    role: 'L1 Log Enrichment & Correlation',
    status: 'Thinking',
    health: 'Healthy',
    permissions: ['Read logs', 'Query threat database', 'Trigger alerts'],
    activity: 'Analyzing Suricata event logs for SSH Brute Force attempts.',
    reasoning: [
      'Ingested 1,245 log lines from suricata.log',
      'Detected 14 consecutive SSH authentication failures from external IP 198.51.100.42 to app-web-01',
      'Cross-referenced 198.51.100.42 against Threat Intelligence feeds; matched AlienVault malicious registry with 98% threat score',
      'Determined high-confidence brute-force attack in progress',
      'Generating alert incident and notifying Response Agent.'
    ]
  },
  {
    id: 'ag-2',
    name: 'Forensic Agent',
    role: 'Deep Host & Memory Analytics',
    status: 'Idle',
    health: 'Healthy',
    permissions: ['Read filesystem', 'Process inspection', 'Memory analysis'],
    activity: 'Idle. Monitoring host state for integrity changes.',
    reasoning: [
      'Completed file integrity integrity scan on /usr/sbin/nginx',
      'Identified binary modifications matching unknown checksums',
      'Extracted active processes; no rogue daemon running from nginx PID namespace',
      'Marked vulnerability CVE-2024-3094 as a potential prerequisite',
      'Submitted full file report to Sandbox Analysis'
    ]
  },
  {
    id: 'ag-3',
    name: 'Response Agent',
    role: 'Automated Threat Mitigation',
    status: 'Active',
    health: 'Healthy',
    permissions: ['Write firewalls', 'Kill processes', 'Isolate endpoints'],
    activity: 'Deploying IP block on boundary firewall rules.',
    reasoning: [
      'Received brute-force alert from Triage Agent',
      'Verified active session state for source 198.51.100.42',
      'Evaluated compliance impact of host isolation; app-web-01 is public facing frontend, host isolation denied',
      'Formulating network level mitigation plan',
      'Executing firewalld block rule for IP 198.51.100.42 on app-web-01 boundary card'
    ]
  }
];

export const mockWorkflows: AutomationWorkflow[] = [
  {
    id: 'wf-1',
    name: 'Brute Force Auto-Mitigation',
    type: 'Response',
    status: 'Active',
    steps: ['Ingest logs', 'Detect threshold (10 failures)', 'Query IOC DB', 'Block IP at firewall', 'Open Incident'],
    lastRun: '2026-07-16 23:01:12',
    successRate: 98.4
  },
  {
    id: 'wf-2',
    name: 'Sandbox Binary Verification',
    type: 'Analysis',
    status: 'Active',
    steps: ['Monitor FIM download folder', 'Submit exe to Sandbox', 'Parse sandbox report', 'If score > 70, flag system'],
    lastRun: '2026-07-16 22:58:20',
    successRate: 100
  },
  {
    id: 'wf-3',
    name: 'CVE Auto-Scan & Correlate',
    type: 'Detection',
    status: 'Inactive',
    steps: ['Pull NVD Vulnerabilities', 'Check asset packages DB', 'Link affected devices', 'Notify Admins'],
    lastRun: '2026-07-16 12:00:00',
    successRate: 92.1
  }
];

export const mockSandboxSessions: SandboxSession[] = [
  {
    id: 'sb-1',
    filename: 'ransomware_wannacry_variant.exe',
    hash: '8f0a1c...e29b',
    status: 'Completed',
    score: 94,
    time: '2026-07-16 22:15:00',
    behavior: [
      'Attempts to write executable file payload to System32',
      'Modifies registry key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Establishes network connections to Tor exit nodes',
      'Encrypts test documents in C:\\Users\\Administrator\\Documents'
    ],
    filesCreated: [
      'C:\\Windows\\System32\\tasksche.exe',
      'C:\\Users\\Administrator\\Desktop\\@Please_Read_Me@.txt'
    ],
    registryKeys: [
      'HKLM\\SOFTWARE\\WanaCrypt0r\\wd = "C:\\Windows\\System32"'
    ],
    networkCalls: [
      '198.51.100.10:9001 (Tor protocol)',
      '5.2.8.10:443 (HTTP GET payload)'
    ]
  },
  {
    id: 'sb-2',
    filename: 'corporate_invoice_july.lnk',
    hash: 'd41b02...c55a',
    status: 'Completed',
    score: 72,
    time: '2026-07-16 21:40:00',
    behavior: [
      'Launches powershell.exe with base64 encoded parameters',
      'Downloads payload script from raw.githubusercontent.com',
      'Queries domain controller for active user groups'
    ],
    filesCreated: [
      'C:\\Users\\User\\AppData\\Local\\Temp\\helper.ps1'
    ],
    registryKeys: [],
    networkCalls: [
      '185.199.108.133:443 (githubusercontent)'
    ]
  }
];

export const mockIncidents: Incident[] = [
  {
    id: 'INC-2026-001',
    title: 'Unauthorized Binary Modification on Web Server',
    severity: 'Critical',
    status: 'Investigating',
    assignedTo: 'Sarah Connor',
    openedAt: '2026-07-16 23:03:10',
    timeline: [
      { time: '23:03:00', event: 'File integrity violation detected on app-web-01 (/usr/sbin/nginx)' },
      { time: '23:03:10', event: 'Incident ticket automatically created by Aegis Triage Agent' },
      { time: '23:05:00', event: 'Analyst Sarah Connor assigned to ticket' }
    ],
    evidence: ['/usr/sbin/nginx (Hash changed)', 'process_list_dump.txt'],
    comments: [
      { user: 'Sarah Connor', time: '23:06:01', text: 'I am running memory analysis now. Nginx is serving traffic, but hash does not match apt repository. Investigating possible zero-day backdoor.' }
    ],
    eventsCount: 3
  },
  {
    id: 'INC-2026-002',
    title: 'Active Network Brute Force on SSH Ports',
    severity: 'High',
    status: 'Resolved',
    assignedTo: 'John Connor',
    openedAt: '2026-07-16 23:01:10',
    timeline: [
      { time: '23:01:00', event: 'SSH brute force rules triggered on Suricata IDS (source: 198.51.100.42)' },
      { time: '23:01:10', event: 'Incident generated & assigned to Automation Response' },
      { time: '23:01:12', event: 'Firewall rules deployed. IP 198.51.100.42 blocked. Verification succeeded.' },
      { time: '23:01:15', event: 'Incident marked resolved by Response Agent' }
    ],
    evidence: ['Suricata alert payload raw dump', 'IP blocked iptables status'],
    comments: [
      { user: 'Response Agent', time: '23:01:12', text: 'Automatic mitigation complete. Traffic from attacker host has dropped to zero.' }
    ],
    eventsCount: 4
  }
];

export const mockAuditLogs: AuditLog[] = [
  {
    id: 'alog-1',
    time: '23:05:11',
    user: 'Sarah Connor',
    action: 'Viewed Incident Details INC-2026-001',
    module: 'Incident Management',
    ip: '10.0.10.220',
    status: 'Success'
  },
  {
    id: 'alog-2',
    time: '23:01:12',
    user: 'Response Agent (API)',
    action: 'Appended IPTables Block Rule [IP: 198.51.100.42]',
    module: 'Security Automation',
    ip: '127.0.0.1',
    status: 'Success'
  },
  {
    id: 'alog-3',
    time: '22:45:00',
    user: 'System Admin',
    action: 'Disabled Rule "2001844 - Cleartext Password HTTP"',
    module: 'Intrusion Detection',
    ip: '10.0.10.104',
    status: 'Success'
  },
  {
    id: 'alog-4',
    time: '22:30:15',
    user: 'Intruder',
    action: 'API Key Generation Request',
    module: 'Settings / Authentication',
    ip: '185.220.101.4',
    status: 'Failed'
  }
];
