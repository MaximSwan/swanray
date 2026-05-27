'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const Store = require('electron-store');

const { parseVlessUrl } = require('./src/vless-parser');
const { buildSingBoxConfig } = require('./src/singbox-config');
const { SingBoxManager } = require('./src/singbox-manager');

const store = new Store({
  name: 'swanray-settings',
  defaults: {
    vlessUrl: '',
    proxyPrograms: [],
    excludeRu: false,
    mixedPort: 2080,
  },
});

// В dev `app.getAppPath()` = корень проекта (есть папка bin/).
// В собранном виде ресурсы лежат в `process.resourcesPath` (electron-builder
// кладёт extraResources в %APP%/resources/).
const BIN_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'bin', 'sing-box.exe')
  : path.join(app.getAppPath(), 'bin', 'sing-box.exe');
const WORK_DIR = path.join(app.getPath('userData'), 'singbox');

const manager = new SingBoxManager({
  binaryPath: BIN_PATH,
  workDir: WORK_DIR,
});

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 680,
    minWidth: 720,
    minHeight: 520,
    title: 'Swanray VPN',
    backgroundColor: '#0f1115',
    icon: path.join(__dirname, 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function broadcast(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

manager.on('log', (line) => {
  broadcast('singbox:log', { time: Date.now(), line });
});
manager.on('started', () => {
  broadcast('singbox:status', { status: 'connected' });
});
manager.on('stopped', () => {
  broadcast('singbox:status', { status: 'disconnected' });
});
manager.on('exit', (info) => {
  broadcast('singbox:status', { status: 'disconnected', exit: info });
});

app.whenReady().then(() => {
  if (!fs.existsSync(WORK_DIR)) {
    fs.mkdirSync(WORK_DIR, { recursive: true });
  }
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', async () => {
  try {
    if (manager.isRunning()) await manager.stop();
  } catch (_) {
    /* ignore */
  }
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', async (event) => {
  if (manager.isRunning()) {
    event.preventDefault();
    try {
      await manager.stop();
    } catch (_) {
      /* ignore */
    }
    app.exit(0);
  }
});

// ---- IPC ----

ipcMain.handle('settings:get', () => {
  return {
    vlessUrl: store.get('vlessUrl'),
    proxyPrograms: store.get('proxyPrograms'),
    excludeRu: store.get('excludeRu'),
    mixedPort: store.get('mixedPort'),
  };
});

ipcMain.handle('settings:set', (_event, partial) => {
  if (partial && typeof partial === 'object') {
    Object.entries(partial).forEach(([key, value]) => {
      store.set(key, value);
    });
  }
  return true;
});

ipcMain.handle('vpn:status', () => {
  return { running: manager.isRunning() };
});

ipcMain.handle('vpn:connect', async (_event, payload) => {
  if (manager.isRunning()) {
    return { ok: false, error: 'VPN уже подключён' };
  }
  try {
    const vless = parseVlessUrl(payload.vlessUrl);
    const config = buildSingBoxConfig({
      vless,
      proxyPrograms: payload.proxyPrograms || [],
      excludeRu: !!payload.excludeRu,
      mixedPort: payload.mixedPort || 2080,
    });

    store.set('vlessUrl', payload.vlessUrl);
    store.set('mixedPort', payload.mixedPort || 2080);
    // proxyPrograms сохраняет renderer через settings:set — здесь не дублируем.

    await manager.start(config);
    return { ok: true, remark: vless.remark, host: vless.host, port: vless.port };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('vpn:disconnect', async () => {
  try {
    await manager.stop();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('dialog:pick-exe', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Выберите исполняемые файлы (.exe), которые ДОЛЖНЫ идти через VPN',
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Исполняемые файлы', extensions: ['exe'] },
      { name: 'Все файлы', extensions: ['*'] },
    ],
  });
  if (result.canceled) return [];
  return result.filePaths.map((p) => ({
    fullPath: p,
    name: path.basename(p),
  }));
});

ipcMain.handle('app:open-bin-folder', async () => {
  const binDir = path.dirname(BIN_PATH);
  if (!fs.existsSync(binDir)) fs.mkdirSync(binDir, { recursive: true });
  await shell.openPath(binDir);
  return binDir;
});

ipcMain.handle('app:bin-info', () => {
  return {
    binaryPath: BIN_PATH,
    exists: fs.existsSync(BIN_PATH),
    workDir: WORK_DIR,
  };
});
