'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  status: $('status'),
  statusText: $('status-text'),
  headerSubtitle: $('header-subtitle'),
  vlessUrl: $('vless-url'),
  parseHint: $('parse-hint'),
  mixedPort: $('mixed-port'),
  btnConnect: $('btn-connect'),
  btnDisconnect: $('btn-disconnect'),
  routeAll: $('route-all'),
  splitBlock: $('split-block'),
  btnPickExe: $('btn-pick-exe'),
  btnPickRunning: $('btn-pick-running'),
  btnClearExe: $('btn-clear-exe'),
  presets: $('presets'),
  exeList: $('exe-list'),
  manualExe: $('manual-exe'),
  procModal: $('proc-modal'),
  procFilter: $('proc-filter'),
  procList: $('proc-list'),
  procClose: $('proc-close'),
  excludeRu: $('exclude-ru'),
  log: $('log'),
  btnClearLog: $('btn-clear-log'),
  binWarning: $('bin-warning'),
  binPath: $('bin-path'),
  btnOpenBin: $('btn-open-bin'),
  linkSingbox: $('link-singbox'),
};

const state = {
  proxyPrograms: [], // [{ name, fullPath?, preset? }] — программы, чей трафик идёт через VPN
  connected: false,
  appPresets: [],
  runningApps: [],
};

function setStatus(name, text) {
  els.status.classList.remove('connected', 'connecting', 'error');
  if (name) els.status.classList.add(name);
  els.statusText.textContent = text;
}

/**
 * Блокирует split tunneling, когда включён «весь трафик» или VPN активен.
 */
function applyRouteAllUi() {
  const routeAll = els.routeAll.checked;
  const splitLocked = routeAll || state.connected;

  els.splitBlock.classList.toggle('is-locked', routeAll);
  els.btnPickExe.disabled = splitLocked;
  els.btnPickRunning.disabled = splitLocked;
  els.btnClearExe.disabled = splitLocked;
  els.manualExe.disabled = splitLocked;
  els.excludeRu.disabled = splitLocked;
  els.exeList.querySelectorAll('button.remove').forEach((b) => {
    b.disabled = splitLocked;
  });
  els.presets.querySelectorAll('button').forEach((b) => {
    b.disabled = splitLocked;
  });

  els.headerSubtitle.textContent = routeAll
    ? 'VLESS-клиент: весь сетевой трафик через VPN'
    : 'VLESS-клиент: VPN только для выбранных программ';
}

/**
 * Блокирует все элементы конфигурации (поля и кнопки), пока VPN активен или
 * пока идёт подключение/отключение. На лету менять VLESS-ключ, порт или
 * список исключений нельзя — sing-box их не подхватит без перезапуска,
 * а пользователь может подумать, что изменения применились.
 */
function setControlsLocked(locked) {
  els.vlessUrl.disabled = locked;
  els.mixedPort.disabled = locked;
  els.routeAll.disabled = locked;
  applyRouteAllUi();
}

function renderExeList() {
  els.exeList.innerHTML = '';
  const removeDisabled = els.routeAll.checked || state.connected;
  state.proxyPrograms.forEach((item, idx) => {
    const li = document.createElement('li');

    const info = document.createElement('div');
    info.className = 'info';
    const nameEl = document.createElement('div');
    nameEl.className = 'name';
    nameEl.textContent = item.name;
    info.appendChild(nameEl);
    const presetMeta = state.appPresets.find((p) => p.id === item.preset);
    if (presetMeta && presetMeta.hint) {
      const hintEl = document.createElement('div');
      hintEl.className = 'hint-line';
      hintEl.textContent = presetMeta.hint;
      info.appendChild(hintEl);
    }
    if (item.fullPath) {
      const pathEl = document.createElement('div');
      pathEl.className = 'path';
      pathEl.textContent = /\\WindowsApps\\/i.test(item.fullPath)
        ? 'Microsoft Store • ' + item.name
        : item.fullPath;
      info.appendChild(pathEl);
    } else if (item.preset === 'chatgpt') {
      const pathEl = document.createElement('div');
      pathEl.className = 'path';
      pathEl.textContent = 'Microsoft Store / OpenAI ChatGPT';
      info.appendChild(pathEl);
    }

    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove';
    removeBtn.textContent = 'Удалить';
    removeBtn.disabled = removeDisabled;
    removeBtn.onclick = () => {
      state.proxyPrograms.splice(idx, 1);
      renderExeList();
      renderPresets();
      persist();
    };

    li.appendChild(info);
    li.appendChild(removeBtn);
    els.exeList.appendChild(li);
  });
}

function inferPresetFromItem(item) {
  if (item && item.preset) return item.preset;
  const n = String((item && item.name) || '').toLowerCase();
  const p = String((item && item.fullPath) || '').toLowerCase();
  if (n === 'code.exe' || p.includes('microsoft vs code')) return 'vscode';
  if (n === 'chatgpt.exe' || n === 'codex.exe' || p.includes('openai.codex') || p.includes('openai.chatgpt')) {
    return 'chatgpt';
  }
  if (n === 'cursor.exe' || /[\\/]cursor[\\/]cursor\.exe$/.test(p)) return 'cursor';
  return undefined;
}

function addProxyProgram(item) {
  if (!item || !item.name) return;
  if (els.routeAll.checked || state.connected) return;
  const name = item.name.trim().toLowerCase();
  if (!name) return;
  const preset = inferPresetFromItem(item);
  if (state.proxyPrograms.some((x) => x.name.toLowerCase() === name)) return;
  if (preset && state.proxyPrograms.some((x) => x.preset === preset)) return;
  state.proxyPrograms.push({
    name: item.name,
    fullPath: item.fullPath || '',
    preset,
  });
  renderExeList();
  renderPresets();
  persist();
}

const PRESET_NAMES = { vscode: 'Code.exe', chatgpt: 'ChatGPT.exe', cursor: 'Cursor.exe' };

function hasPreset(id) {
  return state.proxyPrograms.some((x) => x.preset === id || x.name.toLowerCase() === (PRESET_NAMES[id] || '').toLowerCase());
}

function renderPresets() {
  els.presets.innerHTML = '';
  if (!state.appPresets.length) return;
  const locked = els.routeAll.checked || state.connected;
  state.appPresets.forEach((preset) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'preset-btn' + (hasPreset(preset.id) ? ' is-on' : '');
    btn.textContent = preset.found ? preset.title : `${preset.title} (имя процесса)`;
    btn.title = preset.path || preset.hint || preset.name;
    btn.disabled = locked;
    btn.onclick = async () => {
      if (hasPreset(preset.id)) {
        state.proxyPrograms = state.proxyPrograms.filter((x) => {
          if (x.preset === preset.id) return false;
          if (x.name.toLowerCase() === preset.name.toLowerCase()) return false;
          return true;
        });
        renderExeList();
        renderPresets();
        persist();
        return;
      }
      const item = await window.api.getPresetItem(preset.id);
      addProxyProgram(item || { name: preset.name, fullPath: preset.path || '', preset: preset.id });
    };
    els.presets.appendChild(btn);
  });
}

function closeProcModal() {
  els.procModal.hidden = true;
  els.procFilter.value = '';
}

function renderRunningList() {
  const q = els.procFilter.value.trim().toLowerCase();
  els.procList.innerHTML = '';
  const locked = els.routeAll.checked || state.connected;
  state.runningApps
    .filter((app) => {
      if (!q) return true;
      return app.name.toLowerCase().includes(q) || (app.fullPath || '').toLowerCase().includes(q);
    })
    .forEach((app) => {
      const li = document.createElement('li');
      const info = document.createElement('div');
      info.className = 'info';
      const nameEl = document.createElement('div');
      nameEl.className = 'name';
      nameEl.textContent = app.name;
      info.appendChild(nameEl);
      if (app.fullPath) {
        const pathEl = document.createElement('div');
        pathEl.className = 'path';
        pathEl.textContent = app.fullPath;
        info.appendChild(pathEl);
      }
      li.appendChild(info);
      li.onclick = () => {
        if (locked) return;
        addProxyProgram(app);
        closeProcModal();
      };
      els.procList.appendChild(li);
    });
}

async function openProcModal() {
  if (els.routeAll.checked || state.connected) return;
  els.procModal.hidden = false;
  els.procList.innerHTML = '';
  const empty = document.createElement('li');
  empty.innerHTML = '<div class="info"><div class="name">Загрузка…</div></div>';
  els.procList.appendChild(empty);
  state.runningApps = (await window.api.getRunningApps()) || [];
  renderRunningList();
  els.procFilter.focus();
}

async function persist() {
  await window.api.setSettings({
    vlessUrl: els.vlessUrl.value,
    proxyPrograms: state.proxyPrograms,
    excludeRu: els.excludeRu.checked,
    routeAll: els.routeAll.checked,
    mixedPort: parseInt(els.mixedPort.value, 10) || 2080,
  });
}

function appendLog(text) {
  const wasAtBottom = els.log.scrollHeight - els.log.clientHeight <= els.log.scrollTop + 20;
  els.log.textContent += text + '\n';
  // Ограничиваем размер лога
  if (els.log.textContent.length > 200_000) {
    els.log.textContent = els.log.textContent.slice(-150_000);
  }
  if (wasAtBottom) els.log.scrollTop = els.log.scrollHeight;
}

function previewVless(url) {
  if (!url || !url.trim()) {
    els.parseHint.textContent = '';
    els.parseHint.style.color = '';
    return;
  }
  // Лёгкий парс прямо в renderer — только для подсказки.
  try {
    if (!url.toLowerCase().startsWith('vless://')) throw new Error('должен начинаться с vless://');
    const u = new URL('http://' + url.trim().slice(8));
    const remark = u.hash ? decodeURIComponent(u.hash.slice(1)) : '';
    const sec = u.searchParams.get('security') || 'none';
    const type = u.searchParams.get('type') || 'tcp';
    els.parseHint.style.color = '';
    els.parseHint.textContent = `OK: ${u.hostname}:${u.port} • transport=${type} • security=${sec}${remark ? ' • ' + remark : ''}`;
  } catch (e) {
    els.parseHint.style.color = 'var(--red)';
    els.parseHint.textContent = 'Невалидный ключ: ' + e.message;
  }
}

async function connect() {
  if (state.connected) return;
  const url = els.vlessUrl.value.trim();
  if (!url) {
    setStatus('error', 'Введите VLESS ключ');
    return;
  }
  setStatus('connecting', 'Подключение… (потребуется UAC)');
  els.btnConnect.disabled = true;
  setControlsLocked(true);

  const res = await window.api.connect({
    vlessUrl: url,
    // Передаём объекты {name, fullPath} как есть — fullPath даёт более
    // надёжный матч в sing-box (process_path), независимо от регистра имени.
    proxyPrograms: state.proxyPrograms.map((p) => ({
      name: p.name,
      fullPath: p.fullPath || '',
      preset: p.preset || undefined,
    })),
    excludeRu: els.excludeRu.checked,
    routeAll: els.routeAll.checked,
    mixedPort: parseInt(els.mixedPort.value, 10) || 2080,
  });

  if (!res.ok) {
    setStatus('error', 'Ошибка: ' + res.error);
    els.btnConnect.disabled = false;
    setControlsLocked(false);
    appendLog('[error] ' + res.error);
    return;
  }
  state.connected = true;
  els.btnDisconnect.disabled = false;
  setStatus('connected', `Подключено${res.remark ? ' • ' + res.remark : ''} (${res.host}:${res.port})`);
}

async function disconnect() {
  if (!state.connected) return;
  setStatus('connecting', 'Отключение…');
  els.btnDisconnect.disabled = true;
  const res = await window.api.disconnect();
  if (!res.ok) {
    appendLog('[error] disconnect: ' + res.error);
  }
  state.connected = false;
  els.btnConnect.disabled = false;
  setControlsLocked(false);
  setStatus('', 'Отключено');
}

async function init() {
  const settings = await window.api.getSettings();
  if (settings.vlessUrl) els.vlessUrl.value = settings.vlessUrl;
  if (settings.mixedPort) els.mixedPort.value = settings.mixedPort;
  if (Array.isArray(settings.proxyPrograms)) {
    state.proxyPrograms = settings.proxyPrograms.map((p) => ({
      ...p,
      preset: inferPresetFromItem(p),
    }));
    renderExeList();
  }
  try {
    state.appPresets = (await window.api.getAppPresets()) || [];
  } catch (_) {
    state.appPresets = [];
  }
  renderExeList();
  renderPresets();
  els.excludeRu.checked = !!settings.excludeRu;
  els.routeAll.checked = !!settings.routeAll;
  previewVless(els.vlessUrl.value);
  applyRouteAllUi();
  persist().catch(() => {});

  const binInfo = await window.api.getBinInfo();
  if (!binInfo.exists) {
    els.binWarning.hidden = false;
    els.binPath.textContent = binInfo.binaryPath;
  }

  const status = await window.api.getStatus();
  if (status.running) {
    state.connected = true;
    els.btnConnect.disabled = true;
    els.btnDisconnect.disabled = false;
    setControlsLocked(true);
    renderExeList();
    setStatus('connected', 'Подключено');
  } else {
    setStatus('', 'Отключено');
  }

  window.api.onLog(({ line }) => appendLog(line));
  window.api.onStatus(({ status: s, exit }) => {
    if (s === 'connected') {
      state.connected = true;
      els.btnConnect.disabled = true;
      els.btnDisconnect.disabled = false;
      setControlsLocked(true);
      renderExeList();
    } else if (s === 'disconnected') {
      state.connected = false;
      els.btnConnect.disabled = false;
      els.btnDisconnect.disabled = true;
      setControlsLocked(false);
      renderExeList();
      if (exit && exit.code !== 0) {
        setStatus('error', 'sing-box завершился с ошибкой');
        if (exit.stderr) appendLog('[stderr] ' + exit.stderr);
        if (exit.error) appendLog('[error] ' + exit.error);
      } else {
        setStatus('', 'Отключено');
      }
    }
  });

  els.btnConnect.addEventListener('click', connect);
  els.btnDisconnect.addEventListener('click', disconnect);

  els.btnPickExe.addEventListener('click', async () => {
    if (els.routeAll.checked || state.connected) return;
    const files = await window.api.pickExe();
    files.forEach((f) => addProxyProgram(f));
  });

  els.btnPickRunning.addEventListener('click', () => {
    openProcModal().catch((e) => appendLog('[error] ' + (e && e.message ? e.message : String(e))));
  });
  els.procClose.addEventListener('click', closeProcModal);
  els.procModal.addEventListener('click', (e) => {
    if (e.target === els.procModal) closeProcModal();
  });
  els.procFilter.addEventListener('input', renderRunningList);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !els.procModal.hidden) closeProcModal();
  });

  els.btnClearExe.addEventListener('click', () => {
    if (els.routeAll.checked || state.connected) return;
    state.proxyPrograms = [];
    renderExeList();
    renderPresets();
    persist();
  });

  els.manualExe.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const name = els.manualExe.value.trim();
      if (name) {
        addProxyProgram({ name, fullPath: '' });
        els.manualExe.value = '';
      }
    }
  });

  els.vlessUrl.addEventListener('input', () => {
    previewVless(els.vlessUrl.value);
    persist();
  });

  els.mixedPort.addEventListener('change', persist);
  els.excludeRu.addEventListener('change', persist);
  els.routeAll.addEventListener('change', () => {
    applyRouteAllUi();
    renderExeList();
    persist();
  });

  els.btnClearLog.addEventListener('click', () => {
    els.log.textContent = '';
  });

  els.btnOpenBin.addEventListener('click', () => window.api.openBinFolder());
  els.linkSingbox.addEventListener('click', (e) => {
    e.preventDefault();
    // open external in default browser через shell
    window.open('https://github.com/SagerNet/sing-box/releases');
  });
}

init().catch((e) => {
  appendLog('[fatal] ' + (e && e.message ? e.message : String(e)));
});
