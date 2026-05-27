'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  status: $('status'),
  statusText: $('status-text'),
  vlessUrl: $('vless-url'),
  parseHint: $('parse-hint'),
  mixedPort: $('mixed-port'),
  btnConnect: $('btn-connect'),
  btnDisconnect: $('btn-disconnect'),
  btnPickExe: $('btn-pick-exe'),
  btnClearExe: $('btn-clear-exe'),
  exeList: $('exe-list'),
  manualExe: $('manual-exe'),
  log: $('log'),
  btnClearLog: $('btn-clear-log'),
  binWarning: $('bin-warning'),
  binPath: $('bin-path'),
  btnOpenBin: $('btn-open-bin'),
  linkSingbox: $('link-singbox'),
};

const state = {
  bypassPrograms: [], // [{ name, fullPath? }]
  connected: false,
};

function setStatus(name, text) {
  els.status.classList.remove('connected', 'connecting', 'error');
  if (name) els.status.classList.add(name);
  els.statusText.textContent = text;
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
  els.btnPickExe.disabled = locked;
  els.btnClearExe.disabled = locked;
  els.manualExe.disabled = locked;
  els.exeList.querySelectorAll('button.remove').forEach((b) => { b.disabled = locked; });
}

function renderExeList() {
  els.exeList.innerHTML = '';
  state.bypassPrograms.forEach((item, idx) => {
    const li = document.createElement('li');

    const info = document.createElement('div');
    info.className = 'info';
    const nameEl = document.createElement('div');
    nameEl.className = 'name';
    nameEl.textContent = item.name;
    info.appendChild(nameEl);
    if (item.fullPath) {
      const pathEl = document.createElement('div');
      pathEl.className = 'path';
      pathEl.textContent = item.fullPath;
      info.appendChild(pathEl);
    }

    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove';
    removeBtn.textContent = 'Удалить';
    removeBtn.disabled = state.connected;
    removeBtn.onclick = () => {
      state.bypassPrograms.splice(idx, 1);
      renderExeList();
      persist();
    };

    li.appendChild(info);
    li.appendChild(removeBtn);
    els.exeList.appendChild(li);
  });
}

function addBypass(item) {
  if (!item || !item.name) return;
  const name = item.name.trim().toLowerCase();
  if (!name) return;
  if (state.bypassPrograms.some((x) => x.name.toLowerCase() === name)) return;
  state.bypassPrograms.push({ name: item.name, fullPath: item.fullPath });
  renderExeList();
  persist();
}

async function persist() {
  await window.api.setSettings({
    vlessUrl: els.vlessUrl.value,
    bypassPrograms: state.bypassPrograms,
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
    bypassPrograms: state.bypassPrograms.map((p) => p.name),
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
  if (Array.isArray(settings.bypassPrograms)) {
    state.bypassPrograms = settings.bypassPrograms;
    renderExeList();
  }
  previewVless(els.vlessUrl.value);

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
    const files = await window.api.pickExe();
    files.forEach((f) => addBypass(f));
  });

  els.btnClearExe.addEventListener('click', () => {
    state.bypassPrograms = [];
    renderExeList();
    persist();
  });

  els.manualExe.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const name = els.manualExe.value.trim();
      if (name) {
        addBypass({ name, fullPath: '' });
        els.manualExe.value = '';
      }
    }
  });

  els.vlessUrl.addEventListener('input', () => {
    previewVless(els.vlessUrl.value);
    persist();
  });

  els.mixedPort.addEventListener('change', persist);

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
