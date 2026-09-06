'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

/**
 * Пресеты программ, которые часто нельзя выбрать файловым диалогом
 * (Microsoft Store / WindowsApps) или которые ходят в сеть через helper-процессы.
 *
 * process_name в sing-box на Windows — ТОЧНОЕ сравнение filepath.Base(path),
 * регистр важен. Поэтому для надёжности всегда добавляем process_path_regex с (?i).
 */
const PRESETS = [
  {
    id: 'vscode',
    title: 'VS Code',
    hint: 'включая helper-процессы из папки VS Code',
    names: ['Code.exe'],
    extraNames: ['code-tunnel.exe', 'Code - Insiders.exe'],
    pathRegexes: [
      '(?i).*[\\\\/]Microsoft VS Code[\\\\/].*',
      '(?i).*[\\\\/]Microsoft VS Code Insiders[\\\\/].*',
    ],
  },
  {
    id: 'chatgpt',
    title: 'ChatGPT',
    hint: 'Store-приложение + helper Codex (codex.exe)',
    names: ['ChatGPT.exe'],
    extraNames: ['codex.exe'],
    pathRegexes: [
      '(?i).*[\\\\/]ChatGPT\\.exe$',
      '(?i).*[\\\\/]WindowsApps[\\\\/].*OpenAI\\.(ChatGPT|Codex).*',
      '(?i).*[\\\\/]OpenAI[\\\\/](ChatGPT|Codex)[\\\\/].*',
    ],
  },
  {
    id: 'cursor',
    title: 'Cursor',
    hint: 'включая процессы Cursor',
    names: ['Cursor.exe'],
    extraNames: [],
    pathRegexes: ['(?i).*[\\\\/]Cursor\\.exe$'],
  },
];

const PRESET_BY_ID = Object.fromEntries(PRESETS.map((p) => [p.id, p]));

const DEFAULT_PRESET_IDS = ['vscode', 'chatgpt'];

const SKIP_PROCESS_NAMES = new Set([
  'svchost.exe',
  'csrss.exe',
  'smss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'winlogon.exe',
  'conhost.exe',
  'dllhost.exe',
  'runtimebroker.exe',
  'sihost.exe',
  'taskhostw.exe',
  'fontdrvhost.exe',
  'dwm.exe',
  'unsecapp.exe',
  'searchhost.exe',
  'startmenuexperiencehost.exe',
  'textinputhost.exe',
  'shellexperiencehost.exe',
  'securityhealthservice.exe',
  'system',
  'registry.exe',
  'idle.exe',
]);

function existingPaths(candidates) {
  const out = [];
  for (const p of candidates) {
    if (p && fs.existsSync(p)) out.push(p);
  }
  return out;
}

function uniquePaths(list) {
  const seen = new Set();
  const out = [];
  for (const p of list) {
    if (!p) continue;
    const key = p.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

function runPowerShell(command, timeout = 15000) {
  const r = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
    { encoding: 'utf8', windowsHide: true, timeout }
  );
  if (r.error) throw r.error;
  return (r.stdout || '').trim();
}

function parseJsonArray(text) {
  if (!text) return [];
  try {
    const data = JSON.parse(text);
    return Array.isArray(data) ? data : data ? [data] : [];
  } catch (_) {
    return [];
  }
}

function parsePsStringList(out) {
  if (!out) return [];
  if (out.startsWith('[') || out.startsWith('{') || out.startsWith('"')) {
    const parsed = parseJsonArray(out.startsWith('"') ? `[${out}]` : out);
    return parsed.filter((p) => typeof p === 'string' && p);
  }
  return out
    .split(/\r?\n/)
    .map((s) => s.trim().replace(/^"|"$/g, ''))
    .filter(Boolean);
}

function discoverAppxChatGpt() {
  if (process.platform !== 'win32') return [];
  try {
    const out = runPowerShell(
      `@(Get-AppxPackage | Where-Object { $_.Name -match 'OpenAI|ChatGPT' } | ForEach-Object { $p = Join-Path $_.InstallLocation 'app\\ChatGPT.exe'; if (Test-Path -LiteralPath $p) { $p } }) | ConvertTo-Json -Compress`
    );
    return parsePsStringList(out).filter((s) => /ChatGPT\.exe$/i.test(s));
  } catch (_) {
    return [];
  }
}

function discoverRunningByName(exeNames) {
  if (process.platform !== 'win32') return [];
  const names = exeNames.map((n) => n.replace(/\.exe$/i, ''));
  if (!names.length) return [];
  const filter = names.map((n) => `$_.ProcessName -ieq '${n.replace(/'/g, "''")}'`).join(' -or ');
  try {
    const out = runPowerShell(
      `@(Get-Process | Where-Object { ($_.Path) -and (${filter}) } | Select-Object -ExpandProperty Path -Unique) | ConvertTo-Json -Compress`
    );
    return parsePsStringList(out).filter((s) => /\.exe$/i.test(s));
  } catch (_) {
    return [];
  }
}

function discoverPresetPaths(preset) {
  const env = process.env;
  const local = env.LOCALAPPDATA || '';
  const pf = env.ProgramFiles || '';
  const pf86 = env['ProgramFiles(x86)'] || '';

  let candidates = [];
  if (preset.id === 'vscode') {
    candidates = [
      path.join(local, 'Programs', 'Microsoft VS Code', 'Code.exe'),
      path.join(pf, 'Microsoft VS Code', 'Code.exe'),
      path.join(pf86, 'Microsoft VS Code', 'Code.exe'),
      path.join(local, 'Programs', 'Microsoft VS Code Insiders', 'Code - Insiders.exe'),
    ];
  } else if (preset.id === 'chatgpt') {
    candidates = [
      path.join(local, 'Programs', 'ChatGPT', 'ChatGPT.exe'),
      path.join(local, 'Programs', 'chatgpt', 'ChatGPT.exe'),
    ];
  } else if (preset.id === 'cursor') {
    candidates = [
      path.join(pf, 'cursor', 'Cursor.exe'),
      path.join(pf, 'Cursor', 'Cursor.exe'),
      path.join(local, 'Programs', 'cursor', 'Cursor.exe'),
      path.join(local, 'Programs', 'Cursor', 'Cursor.exe'),
    ];
  }

  const found = existingPaths(candidates);
  if (preset.id === 'chatgpt') {
    found.push(...discoverAppxChatGpt());
  }
  found.push(...discoverRunningByName([...preset.names, ...(preset.extraNames || [])]));
  return uniquePaths(found);
}

function inferPresetId(item) {
  const name = path.basename((item && item.name) || '').toLowerCase();
  const full = String((item && item.fullPath) || '').toLowerCase();
  if (item && item.preset && PRESET_BY_ID[item.preset]) return item.preset;
  if (name === 'code.exe' || name === 'code - insiders.exe' || full.includes('microsoft vs code')) {
    return 'vscode';
  }
  if (
    name === 'chatgpt.exe' ||
    name === 'codex.exe' ||
    full.includes('openai.chatgpt') ||
    full.includes('openai.codex') ||
    full.includes('\\openai\\chatgpt') ||
    full.includes('\\openai\\codex')
  ) {
    return 'chatgpt';
  }
  if (name === 'cursor.exe' || /[\\/]cursor[\\/]cursor\.exe$/.test(full)) {
    return 'cursor';
  }
  return null;
}

function nameCaseVariants(name) {
  const base = path.basename(String(name || '').trim());
  if (!base) return [];
  const withExe = /\.exe$/i.test(base) ? base : `${base}.exe`;
  const noExt = withExe.slice(0, -4);
  const variants = new Set([
    withExe,
    withExe.toLowerCase(),
    withExe.toUpperCase(),
    noExt.charAt(0).toUpperCase() + noExt.slice(1).toLowerCase() + '.exe',
  ]);
  return [...variants];
}

function isUnstablePath(fullPath) {
  const p = String(fullPath || '');
  return /\\WindowsApps\\/i.test(p) || /\\OpenAI\\Codex\\bin\\/i.test(p);
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Разворачивает список программ в то, что реально нужно sing-box.
 * @returns {{ processNames: string[], processPaths: string[], processPathRegexes: string[] }}
 */
function expandForSingBox(proxyPrograms) {
  const seenNames = new Set();
  const processNames = [];
  const processPaths = [];
  const regexes = new Set();
  const appliedPresets = new Set();

  const addName = (name) => {
    for (const variant of nameCaseVariants(name)) {
      if (seenNames.has(variant)) continue;
      seenNames.add(variant);
      processNames.push(variant);
    }
  };

  const addPath = (fullPath) => {
    const p = String(fullPath || '').trim();
    if (!p || isUnstablePath(p)) return;
    if (processPaths.some((x) => x.toLowerCase() === p.toLowerCase())) return;
    processPaths.push(p);
    regexes.add(`(?i)^${escapeRegExp(p.replace(/\//g, '\\')).replace(/\\\\/g, '[\\\\/]')}$`);
  };

  const applyPreset = (preset) => {
    if (!preset || appliedPresets.has(preset.id)) return;
    appliedPresets.add(preset.id);
    for (const n of preset.names) addName(n);
    for (const n of preset.extraNames || []) addName(n);
    for (const rx of preset.pathRegexes || []) regexes.add(rx);
    for (const p of discoverPresetPaths(preset)) addPath(p);
  };

  for (const raw of proxyPrograms || []) {
    if (!raw) continue;
    const obj = typeof raw === 'string' ? { name: raw } : raw;
    let name = (obj.name || '').trim();
    const fullPath = (obj.fullPath || '').trim();
    if (!name && fullPath) name = path.basename(fullPath);
    if (!name) continue;
    name = path.basename(name);

    const presetId = inferPresetId({ name, fullPath, preset: obj.preset });
    if (presetId) applyPreset(PRESET_BY_ID[presetId]);

    addName(name);
    addPath(fullPath);
  }

  return {
    processNames,
    processPaths,
    processPathRegexes: [...regexes],
  };
}

function makeProgramItem(presetId) {
  const preset = PRESET_BY_ID[presetId];
  if (!preset) return null;
  const paths = discoverPresetPaths(preset);
  return {
    name: preset.names[0],
    fullPath: paths[0] || '',
    preset: preset.id,
  };
}

function seedDefaultPrograms(existing) {
  const list = Array.isArray(existing) ? [...existing] : [];
  const have = new Set(list.map((x) => inferPresetId(x)).filter(Boolean));
  for (const id of DEFAULT_PRESET_IDS) {
    if (have.has(id)) continue;
    const item = makeProgramItem(id);
    if (item) list.push(item);
  }
  return list;
}

function listPresetStatus() {
  return PRESETS.map((preset) => {
    const paths = discoverPresetPaths(preset);
    return {
      id: preset.id,
      title: preset.title,
      hint: preset.hint,
      name: preset.names[0],
      found: paths.length > 0,
      path: paths[0] || '',
    };
  });
}

function listRunningProcesses() {
  if (process.platform !== 'win32') return [];
  try {
    const out = runPowerShell(
      `Get-Process | Where-Object { $_.Path } | Select-Object @{n='name';e={$_.ProcessName + '.exe'}}, @{n='fullPath';e={$_.Path}} | Sort-Object name, fullPath -Unique | ConvertTo-Json -Compress`,
      20000
    );
    const rows = parseJsonArray(out);
    const seen = new Set();
    const result = [];
    for (const row of rows) {
      const name = String(row.name || '').trim();
      const fullPath = String(row.fullPath || '').trim();
      if (!name || !fullPath) continue;
      if (SKIP_PROCESS_NAMES.has(name.toLowerCase())) continue;
      const key = fullPath.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      result.push({
        name,
        fullPath,
        preset: inferPresetId({ name, fullPath }),
      });
    }
    result.sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
    return result;
  } catch (_) {
    return [];
  }
}

module.exports = {
  PRESETS,
  DEFAULT_PRESET_IDS,
  expandForSingBox,
  inferPresetId,
  makeProgramItem,
  seedDefaultPrograms,
  listPresetStatus,
  listRunningProcesses,
};
