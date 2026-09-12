const SysTray = require('systray2').default;
const path = require('path');
const os = require('os');
const fs = require('fs');
const { execSync, spawn } = require('child_process');

const settingsDir = path.join(process.env.APPDATA || os.homedir(), 'AegisCore');
const settingsFile = path.join(settingsDir, 'settings.json');

if (!fs.existsSync(settingsDir)) {
  fs.mkdirSync(settingsDir, { recursive: true });
}

let settings = { autoStart: false, port: 3000, backendPort: 9009 };
if (fs.existsSync(settingsFile)) {
  try {
    settings = { ...settings, ...JSON.parse(fs.readFileSync(settingsFile, 'utf8')) };
  } catch (e) {}
}

const saveSettings = () => {
  fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
};

const setAutoStart = (enable) => {
  const nodeExe = process.execPath;
  const scriptPath = path.resolve(__dirname, 'tray.js');
  try {
    if (enable) {
      execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "AegisCore" /t REG_SZ /d "\"${nodeExe}\" \"${scriptPath}\"" /f`);
    } else {
      execSync('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "AegisCore" /f');
    }
  } catch (e) {
    console.error('Failed to set autostart', e);
  }
};

const iconBase64 = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABTSURBVFhH7c6xCQAgEATB+0/a18I+LAwbMYMw+4qX1L1nO+/5P2fP1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMCdB1BfC7fJ2qHMAAAAAElFTkSuQmCC";

const systray = new SysTray({
  menu: {
    icon: iconBase64,
    isTemplateIcon: os.platform() === 'darwin',
    title: "",
    tooltip: "AegisCore Security Platform",
    items: [
      {
        title: "[ AegisCore Security Platform - Backend: CHECKING ]",
        tooltip: "",
        checked: false,
        enabled: false
      },
      {
        title: "[ ------------------------------------------- ]",
        tooltip: "",
        checked: false,
        enabled: false
      },
      {
        title: "[ Open Dashboard (localhost:" + settings.port + ") ]",
        tooltip: "",
        checked: false,
        enabled: true
      },
      {
        title: "[ Restart Dashboard Server ]",
        tooltip: "",
        checked: false,
        enabled: true
      },
      {
        title: "[ Check Backend Status ]",
        tooltip: "",
        checked: false,
        enabled: true
      },
      {
        title: "[ ------------------------------------------- ]",
        tooltip: "",
        checked: false,
        enabled: false
      },
      {
        title: "[ Settings: Disable Auto-Start ]",
        tooltip: "",
        checked: settings.autoStart,
        enabled: true
      },
      {
        title: "[ Settings: Quit on Close ]",
        tooltip: "",
        checked: false,
        enabled: true
      },
      {
        title: "[ ------------------------------------------- ]",
        tooltip: "",
        checked: false,
        enabled: false
      },
      {
        title: "[ Quit AegisCore ]",
        tooltip: "",
        checked: false,
        enabled: true
      }
    ]
  },
  debug: false,
  copyDir: true
});

let dashboardProcess = null;

const startDashboard = () => {
  if (dashboardProcess) {
    dashboardProcess.kill();
  }
  dashboardProcess = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--port', settings.port.toString()], {
    cwd: __dirname,
    stdio: 'ignore',
    windowsHide: true,
    detached: true
  });
};

const checkBackendStatus = async () => {
  try {
    const res = await fetch(`http://127.0.0.1:${settings.backendPort}/api/v1/health`, { method: 'GET', signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      updateMenuHeader("ONLINE");
    } else {
      updateMenuHeader("OFFLINE");
    }
  } catch (e) {
    updateMenuHeader("OFFLINE");
  }
};

const updateMenuHeader = (status) => {
  systray.sendAction({
    type: 'update-item',
    item: {
      ...systray.internalIdMap[0],
      title: `[ AegisCore Security Platform - Backend: ${status} ]`
    },
    seq_id: 0
  });
};

systray.onClick(action => {
  const item = action.item;
  if (item.title.includes('Open Dashboard')) {
    import('open').then(open => open.default(`http://localhost:${settings.port}`));
  } else if (item.title.includes('Restart Dashboard Server')) {
    startDashboard();
  } else if (item.title.includes('Check Backend Status')) {
    checkBackendStatus();
  } else if (item.title.includes('Auto-Start')) {
    settings.autoStart = !settings.autoStart;
    saveSettings();
    setAutoStart(settings.autoStart);
    systray.sendAction({
      type: 'update-item',
      item: {
        ...item,
        title: settings.autoStart ? "[ Settings: Disable Auto-Start ]" : "[ Settings: Enable Auto-Start ]",
        checked: settings.autoStart
      },
      seq_id: action.seq_id
    });
  } else if (item.title.includes('Quit AegisCore')) {
    if (dashboardProcess) {
      dashboardProcess.kill();
    }
    systray.kill();
    process.exit(0);
  }
});

systray.ready().then(() => {
  if (settings.autoStart) {
    setAutoStart(true);
    systray.sendAction({
      type: 'update-item',
      item: {
        ...systray.internalIdMap[6],
        title: "[ Settings: Disable Auto-Start ]",
        checked: true
      },
      seq_id: 0
    });
  } else {
    systray.sendAction({
      type: 'update-item',
      item: {
        ...systray.internalIdMap[6],
        title: "[ Settings: Enable Auto-Start ]",
        checked: false
      },
      seq_id: 0
    });
  }
  startDashboard();
  checkBackendStatus();
  setInterval(checkBackendStatus, 30000);
  
  setTimeout(() => {
    import('open').then(open => open.default(`http://localhost:${settings.port}`));
  }, 3500);
});
