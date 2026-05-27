'use strict';

const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { EventEmitter } = require('events');

/**
 * Проверяет, запущен ли текущий процесс с правами администратора Windows.
 * Используем "net session" — эта команда требует admin и возвращает 0
 * только в этом случае. Кешируем результат — права в рамках процесса не меняются.
 */
let _cachedIsElevated = null;
function isElevated() {
  if (_cachedIsElevated !== null) return _cachedIsElevated;
  if (process.platform !== 'win32') {
    _cachedIsElevated = process.getuid && process.getuid() === 0;
    return _cachedIsElevated;
  }
  try {
    const r = spawnSync('net', ['session'], { windowsHide: true, stdio: 'ignore' });
    _cachedIsElevated = r.status === 0;
  } catch (_) {
    _cachedIsElevated = false;
  }
  return _cachedIsElevated;
}

/**
 * Менеджер процесса sing-box.
 *
 * Запуск — через PowerShell `Start-Process -Verb RunAs`, что вызывает UAC
 * и запускает sing-box в скрытом окне с правами администратора (требуется для TUN).
 *
 * Остановка — `taskkill /F /IM sing-box.exe`, тоже с правами администратора.
 *
 * stdout/stderr недоступны (процесс в другом контексте безопасности),
 * поэтому sing-box логирует в файл, который мы tail-им.
 */
class SingBoxManager extends EventEmitter {
  /**
   * @param {object} options
   * @param {string} options.binaryPath - путь к sing-box.exe
   * @param {string} options.workDir
   */
  constructor({ binaryPath, workDir }) {
    super();
    this.binaryPath = binaryPath;
    this.workDir = workDir;
    this.configPath = path.join(workDir, 'config.json');
    this.logPath = path.join(workDir, 'singbox.log');
    this.pidPath = path.join(workDir, 'singbox.pid');

    this.running = false;
    this.pid = null;
    this._child = null;
    this._logWatcher = null;
    this._logOffset = 0;
    this._processPoll = null;
  }

  isRunning() {
    return this.running;
  }

  ensureBinary() {
    if (!fs.existsSync(this.binaryPath)) {
      throw new Error(
        'Не найден sing-box.exe по пути: ' +
          this.binaryPath +
          '\nСкачайте бинарник со страницы https://github.com/SagerNet/sing-box/releases ' +
          'и поместите его в папку bin/ рядом с приложением.'
      );
    }
  }

  writeConfig(config) {
    if (!fs.existsSync(this.workDir)) {
      fs.mkdirSync(this.workDir, { recursive: true });
    }
    const cfg = JSON.parse(JSON.stringify(config));
    cfg.log = cfg.log || {};
    cfg.log.output = this.logPath;
    fs.writeFileSync(this.configPath, JSON.stringify(cfg, null, 2), 'utf8');
  }

  /**
   * Экранирует строку для подстановки в PowerShell single-quoted строку:
   * одинарная кавычка → удвоенная одинарная.
   */
  _psEscape(str) {
    return String(str).replace(/'/g, "''");
  }

  /**
   * Запускает произвольную команду от имени администратора (UAC).
   * Резолвится только после успешного создания процесса.
   *
   * Различает три исхода:
   *   exit 0 — успех (если passThru, stdout = PID)
   *   exit 2 — пользователь отклонил UAC (Win32 error 1223 = ERROR_CANCELLED)
   *   exit 3 — любая другая ошибка (stderr содержит текст)
   *
   * @param {string} filePath
   * @param {string} argumentString
   * @param {object} [opts]
   * @param {boolean} [opts.passThru=false]
   * @returns {Promise<{pid?: number}>}
   */
  _runElevated(filePath, argumentString, opts = {}) {
    const passThru = !!opts.passThru;

    const argParts = [
      `-FilePath '${this._psEscape(filePath)}'`,
      `-ArgumentList '${this._psEscape(argumentString)}'`,
      `-Verb RunAs`,
      `-WindowStyle Hidden`,
    ];
    if (passThru) argParts.push('-PassThru');

    const startStmt = `Start-Process ${argParts.join(' ')} -ErrorAction Stop`;
    // UAC-отказ может прилететь как Win32Exception с NativeErrorCode=1223
    // НАПРЯМУЮ или как InnerException внутри обёрток PowerShell — поэтому
    // проходим по всей цепочке InnerException. Также форсируем UTF-8 для
    // stderr, иначе на русской Windows локализованные сообщения приходят
    // в кодировке консоли (cp866) и в Node превращаются в кракозябры.
    const psBody = `
$utf8 = New-Object System.Text.UTF8Encoding $false
$errWriter = New-Object System.IO.StreamWriter([Console]::OpenStandardError(), $utf8)
$errWriter.AutoFlush = $true
[Console]::SetError($errWriter)
[Console]::OutputEncoding = $utf8

function Test-IsUacCancelled($errorRecord) {
  $e = $errorRecord.Exception
  while ($e -ne $null) {
    if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) {
      return $true
    }
    # HRESULT 0x800704C7 == ERROR_CANCELLED, обёрнутый как HRESULT.
    if ($e.HResult -eq -2147023673) { return $true }
    # Fallback: текст. Английская часть приходит напрямую от Windows
    # и не локализуется (даже когда внешняя оболочка — на русском).
    if ($e.Message -match 'operation was canceled by the user' -or
        $e.Message -match 'operation was cancelled by the user' -or
        $e.Message -match '\b1223\b' -or
        $e.Message -match 'отменена пользователем') {
      return $true
    }
    $e = $e.InnerException
  }
  return $false
}

try {
  ${passThru ? `$p = ${startStmt}; Write-Output $p.Id` : startStmt}
  exit 0
} catch {
  if (Test-IsUacCancelled $_) {
    [Console]::Error.WriteLine('UAC_CANCELLED')
    exit 2
  }
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 3
}`.trim();

    return new Promise((resolve, reject) => {
      const ps = spawn(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', psBody],
        { windowsHide: true }
      );

      let stdout = '';
      let stderr = '';
      ps.stdout.on('data', (d) => { stdout += d.toString(); });
      ps.stderr.on('data', (d) => { stderr += d.toString(); });

      ps.on('error', (err) => reject(err));
      ps.on('exit', (code) => {
        if (code === 0) {
          if (passThru) {
            const pid = parseInt(stdout.trim(), 10);
            return resolve({ pid: Number.isFinite(pid) ? pid : undefined });
          }
          return resolve({});
        }
        if (code === 2) {
          return reject(new Error('Запрос прав администратора был отклонён.'));
        }
        const msg = stderr.trim() || `PowerShell завершился с кодом ${code}`;
        reject(new Error(msg));
      });
    });
  }

  async start(config) {
    if (this.running) throw new Error('sing-box уже запущен');
    this.ensureBinary();
    this.writeConfig(config);

    try { fs.writeFileSync(this.logPath, '', 'utf8'); } catch (_) { /* ignore */ }
    this._logOffset = 0;

    if (isElevated()) {
      // Приложение уже запущено с правами администратора (например, в собранном
      // виде с requestedExecutionLevel=requireAdministrator) — UAC не нужен,
      // запускаем sing-box напрямую как дочерний процесс.
      await this._startDirect();
    } else {
      // В dev режиме поднимаемся через PowerShell + Start-Process -Verb RunAs.
      const args = `run -c "${this.configPath}" -D "${this.workDir}"`;
      const result = await this._runElevated(this.binaryPath, args, { passThru: true });
      this.pid = result.pid;
    }

    if (this.pid) {
      try { fs.writeFileSync(this.pidPath, String(this.pid), 'utf8'); } catch (_) { /* ignore */ }
    }

    this.running = true;
    this._startLogWatch();
    this._startProcessPoll();
    this.emit('started');
  }

  /**
   * Запуск sing-box напрямую через child_process.spawn — используется,
   * когда приложение уже работает с правами администратора.
   * В этом случае мы получаем настоящий ChildProcess со stdout/stderr и
   * можем нормально слушать события exit.
   */
  _startDirect() {
    return new Promise((resolve, reject) => {
      const args = ['run', '-c', this.configPath, '-D', this.workDir];
      const child = spawn(this.binaryPath, args, {
        windowsHide: true,
        cwd: this.workDir,
      });

      this._child = child;
      this.pid = child.pid;

      let earlyError = '';
      const onEarlyStderr = (chunk) => {
        earlyError += chunk.toString();
      };
      child.stderr.on('data', onEarlyStderr);
      child.stdout.on('data', (chunk) => {
        chunk.toString().split(/\r?\n/).forEach((l) => {
          const t = l.trim();
          if (t && this._isImportantLogLine(t)) this.emit('log', t);
        });
      });

      child.on('error', (err) => {
        if (!this.running) reject(err);
      });

      child.on('exit', (code) => {
        const wasRunning = this.running;
        this.running = false;
        this._child = null;
        this._stopProcessPoll();
        this._stopLogWatch();
        if (!wasRunning) {
          // упал ещё на старте
          const msg = earlyError.trim() || `sing-box завершился с кодом ${code}`;
          reject(new Error(msg));
        } else {
          this.emit('exit', { code, error: earlyError.trim() || null });
        }
      });

      // Даём sing-box ~600мс на немедленные ошибки старта (битый конфиг и т.п.).
      setTimeout(() => {
        if (this._child === child && !child.exitCode) {
          child.stderr.removeListener('data', onEarlyStderr);
          // дальше stderr пишем в общий лог
          child.stderr.on('data', (chunk) => {
            chunk.toString().split(/\r?\n/).forEach((l) => {
              const t = l.trim();
              if (t && this._isImportantLogLine(t)) this.emit('log', t);
            });
          });
          resolve();
        }
      }, 600);
    });
  }

  async stop() {
    if (!this.running) return;

    // Останавливаем мониторинг ДО kill, чтобы не сгенерировать ложный "exit".
    this._stopProcessPoll();

    if (this._child) {
      // Прямой spawn: пытаемся мягко (Stop-Process без -Force), даём время
      // на откат маршрутов auto_route, затем force-kill если жив.
      await this._gracefulKillDirect();
    } else {
      // Запущено через UAC — sing-box работает с админ-правами, нам нужен UAC
      // и для остановки. Сначала пробуем graceful, потом force.
      try {
        await this._runElevated(
          'powershell.exe',
          this.pid
            ? `-NoProfile -Command "Stop-Process -Id ${this.pid} -ErrorAction SilentlyContinue"`
            : `-NoProfile -Command "Stop-Process -Name sing-box -ErrorAction SilentlyContinue"`,
          { passThru: false }
        );
        // Даём sing-box до 2.5 секунд на корректное закрытие TUN и маршрутов.
        await this._waitForExit(2500);
        if (await this._isProcessAlive()) {
          const args = this.pid ? `/F /PID ${this.pid}` : `/F /IM sing-box.exe`;
          await this._runElevated('taskkill.exe', args, { passThru: false });
        }
      } catch (e) {
        this.emit('log', '[manager] stop error: ' + e.message);
      }
    }

    this.running = false;
    this.pid = null;
    this._child = null;
    try { if (fs.existsSync(this.pidPath)) fs.unlinkSync(this.pidPath); } catch (_) { /* ignore */ }
    this._stopLogWatch();

    // Сбрасываем DNS-кеш Windows: после kill sing-box в кеше остаются записи
    // с TUN-интерфейса, из-за чего пинг и резолв тупят пока кеш не истечёт.
    try {
      spawnSync('ipconfig.exe', ['/flushdns'], { windowsHide: true, timeout: 3000 });
    } catch (_) { /* ignore */ }

    this.emit('stopped');
  }

  /**
   * Мягко завершает дочерний sing-box и ждёт. Если за 2.5с не вышел —
   * прибивает taskkill /F. Мягкое завершение даёт sing-box удалить TUN
   * и откатить маршруты auto_route — иначе сетевой стек на время остаётся
   * с битыми правилами и пинг до серверов растёт.
   */
  async _gracefulKillDirect() {
    try {
      spawnSync('taskkill.exe', ['/PID', String(this.pid)], { windowsHide: true });
    } catch (e) {
      this.emit('log', '[manager] stop error: ' + e.message);
    }
    await this._waitForExit(2500);
    if (this._child && !this._child.exitCode) {
      try {
        spawnSync('taskkill.exe', ['/F', '/T', '/PID', String(this.pid)], { windowsHide: true });
      } catch (_) { /* ignore */ }
    }
  }

  _waitForExit(timeoutMs) {
    return new Promise((resolve) => {
      const start = Date.now();
      const tick = async () => {
        if (Date.now() - start >= timeoutMs) return resolve();
        const alive = await this._isProcessAlive();
        if (!alive) return resolve();
        setTimeout(tick, 150);
      };
      tick();
    });
  }

  /**
   * Поллим, жив ли процесс. Если sing-box упал (например, ошибка конфига) —
   * детектируем это и уведомляем UI.
   */
  _startProcessPoll() {
    this._stopProcessPoll();
    this._processPoll = setInterval(() => {
      this._isProcessAlive().then((alive) => {
        if (!alive && this.running) {
          this.running = false;
          this._stopProcessPoll();
          this._stopLogWatch();
          this.emit('exit', { code: -1, error: 'sing-box процесс завершился (см. логи)' });
        }
      });
    }, 2000);
  }

  _stopProcessPoll() {
    if (this._processPoll) {
      clearInterval(this._processPoll);
      this._processPoll = null;
    }
  }

  _isProcessAlive() {
    return new Promise((resolve) => {
      const filter = this.pid ? `PID eq ${this.pid}` : `IMAGENAME eq sing-box.exe`;
      const ps = spawn('tasklist.exe', ['/FI', filter, '/NH', '/FO', 'CSV'], { windowsHide: true });
      let out = '';
      ps.stdout.on('data', (d) => { out += d.toString(); });
      ps.on('error', () => resolve(false));
      ps.on('exit', () => {
        // tasklist пишет "INFO: No tasks are running..." если не найдено.
        resolve(/sing-box\.exe/i.test(out));
      });
    });
  }

  /**
   * Пропускаем в UI только важные строки: WARN / ERROR / FATAL / PANIC от
   * sing-box и наши собственные сообщения с префиксом [manager].
   * INFO/DEBUG/TRACE от sing-box и шум от роутера (соединения, DNS, sniff)
   * раздувают лог до сотен тысяч строк и подвешивают UI.
   */
  _isImportantLogLine(line) {
    if (!line) return false;
    if (line.startsWith('[manager]')) return true;
    // sing-box формат: "+0000 LEVEL ..." или "LEVEL[0000] ..." (с ANSI-цветами).
    return /\b(WARN|ERROR|FATAL|PANIC)\b/.test(line);
  }

  _startLogWatch() {
    this._stopLogWatch();
    const readNew = () => {
      try {
        const stat = fs.statSync(this.logPath);
        if (stat.size > this._logOffset) {
          const stream = fs.createReadStream(this.logPath, {
            start: this._logOffset,
            end: stat.size,
            encoding: 'utf8',
          });
          let buffer = '';
          stream.on('data', (chunk) => { buffer += chunk; });
          stream.on('end', () => {
            this._logOffset = stat.size;
            if (buffer) {
              buffer.split(/\r?\n/).forEach((line) => {
                const trimmed = line.trim();
                if (trimmed && this._isImportantLogLine(trimmed)) {
                  this.emit('log', trimmed);
                }
              });
            }
          });
        } else if (stat.size < this._logOffset) {
          this._logOffset = 0;
        }
      } catch (_) {
        /* файл ещё не создан */
      }
    };
    this._logWatcher = setInterval(readNew, 1500);
  }

  _stopLogWatch() {
    if (this._logWatcher) {
      clearInterval(this._logWatcher);
      this._logWatcher = null;
    }
  }
}

module.exports = { SingBoxManager };
