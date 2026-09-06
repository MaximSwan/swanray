'use strict';

const { expandForSingBox } = require('./proxy-apps');

/**
 * Строит outbound VLESS из распарсенного URL.
 */
function buildVlessOutbound(vless) {
  const outbound = {
    type: 'vless',
    tag: 'proxy',
    server: vless.host,
    server_port: vless.port,
    uuid: vless.uuid,
    packet_encoding: 'xudp',
  };

  if (vless.flow) {
    outbound.flow = vless.flow;
  }

  if (vless.security === 'tls' || vless.security === 'reality') {
    outbound.tls = {
      enabled: true,
      server_name: vless.sni || vless.host,
      insecure: false,
    };

    if (vless.alpn && vless.alpn.length > 0) {
      outbound.tls.alpn = vless.alpn;
    }

    if (vless.fingerprint) {
      outbound.tls.utls = {
        enabled: true,
        fingerprint: vless.fingerprint,
      };
    }

    if (vless.security === 'reality') {
      outbound.tls.reality = {
        enabled: true,
        public_key: vless.realityPublicKey,
        short_id: vless.realityShortId,
      };
      // Для Reality utls обязателен.
      if (!outbound.tls.utls) {
        outbound.tls.utls = { enabled: true, fingerprint: 'chrome' };
      }
    }
  }

  const transportType = vless.transport;
  if (transportType === 'ws') {
    outbound.transport = {
      type: 'ws',
      path: vless.wsPath || '/',
    };
    if (vless.wsHost) {
      outbound.transport.headers = { Host: vless.wsHost };
    }
  } else if (transportType === 'grpc') {
    outbound.transport = {
      type: 'grpc',
      service_name: vless.grpcServiceName || '',
    };
  } else if (transportType === 'http' || transportType === 'h2') {
    outbound.transport = {
      type: 'http',
      path: vless.wsPath || '/',
    };
    if (vless.wsHost) {
      outbound.transport.host = [vless.wsHost];
    }
  }
  // tcp / по умолчанию — поле transport не нужно.

  return outbound;
}

/**
 * Строит полный конфиг sing-box.
 *
 * По умолчанию — include-only split tunneling: через VPN идут ТОЛЬКО указанные
 * программы, остальное — напрямую. Если routeAll=true — весь трафик через VPN
 * (final: proxy), список программ игнорируется.
 *
 * @param {object} options
 * @param {object} options.vless - объект из parseVlessUrl
 * @param {Array<string|{name?:string, fullPath?:string, preset?:string}>} options.proxyPrograms -
 *   программы, трафик которых пойдёт ЧЕРЕЗ VPN. Можно передавать просто имена
 *   ("Telegram.exe") либо объекты {name, fullPath, preset}. Для vscode/chatgpt/cursor
 *   автоматически добавляются helper-процессы и path_regex.
 * @param {boolean} [options.excludeRu=false] - если true, .ru и .рф домены
 *   идут напрямую (direct). В режиме routeAll игнорируется.
 * @param {boolean} [options.routeAll=false] - весь сетевой трафик через VPN
 * @param {number} [options.mixedPort=2080] - порт для локального HTTP/SOCKS прокси
 * @param {string} [options.logLevel='info']
 */
function buildSingBoxConfig(options) {
  const {
    vless,
    proxyPrograms = [],
    excludeRu = false,
    routeAll = false,
    mixedPort = 2080,
    logLevel = 'warn',
  } = options;

  const proxyOutbound = buildVlessOutbound(vless);

  // process_name в sing-box — точное сравнение basename (регистр важен).
  // Поэтому к именам добавляем path_regex с (?i) и helper-процессы пресетов
  // (VS Code helpers, ChatGPT/codex.exe из WindowsApps).
  const { processNames: proxyProcessNames, processPaths: proxyProcessPaths, processPathRegexes } =
    expandForSingBox(proxyPrograms);

  // ВАЖНО: правила обрабатываются сверху вниз, первое совпавшее побеждает.
  // Порядок критичен — собственные DNS-запросы sing-box должны уходить direct
  // ДО общего hijack-dns правила, иначе они зацикливаются: sing-box → TUN →
  // hijack → DNS-резолвер → upstream через direct → пакет в TUN → hijack...
  const routeRules = [
    // 0. Sniff вынесен из inbound (в 1.13 поля sniff на inbound удалены).
    { action: 'sniff' },
    // 1. Трафик самого sing-box и приложения — всегда direct, мимо TUN и hijack.
    {
      process_name: ['sing-box.exe', 'swanray.exe', 'electron.exe'],
      outbound: 'direct',
    },
    // 2. DNS от всех остальных процессов — перехватываем в DNS-резолвер.
    //    action: 'hijack-dns' обрабатывает запрос внутри sing-box, не маршрутизируя
    //    его через outbound (что иначе создавало бы петлю через TUN).
    {
      protocol: 'dns',
      action: 'hijack-dns',
    },
    // 3. Локальные/приватные адреса — direct.
    {
      ip_is_private: true,
      outbound: 'direct',
    },
  ];

  // 4. Российские домены — только в режиме split tunneling.
  //    В routeAll весь трафик (включая .ru) идёт через VPN.
  if (excludeRu && !routeAll) {
    routeRules.push({
      domain_suffix: ['.ru', '.рф'],
      outbound: 'direct',
    });
  }

  // 5. Выбранные программы — через VPN. В routeAll не нужны: final=proxy.
  if (!routeAll) {
    if (proxyProcessNames.length > 0) {
      routeRules.push({ process_name: proxyProcessNames, outbound: 'proxy' });
    }
    if (proxyProcessPaths.length > 0) {
      routeRules.push({ process_path: proxyProcessPaths, outbound: 'proxy' });
    }
    if (processPathRegexes.length > 0) {
      routeRules.push({ process_path_regex: processPathRegexes, outbound: 'proxy' });
    }
  }

  // Определяем, является ли vless.host доменом (а не IP). Если домен —
  // нужно жёстко резолвить его через local-dns, иначе ещё один loop:
  // proxy outbound для коннекта к серверу запросит резолв через proxy-dns.
  const isIpHost =
    !!vless.host && (/^[0-9.]+$/.test(vless.host) || /^\[?[0-9a-f:]+\]?$/i.test(vless.host));
  const dnsRules = [];
  if (!isIpHost && vless.host) {
    dnsRules.push({ domain: [vless.host], action: 'route', server: 'local-dns' });
  }
  if (vless.sni && vless.sni !== vless.host && !isIpHost) {
    dnsRules.push({ domain: [vless.sni], action: 'route', server: 'local-dns' });
  }
  // Российские домены — local-dns только в split tunneling.
  if (excludeRu && !routeAll) {
    dnsRules.push({ domain_suffix: ['.ru', '.рф'], action: 'route', server: 'local-dns' });
  }
  // В режиме split tunneling — proxy-dns для выбранных программ.
  // В routeAll DNS по умолчанию идёт через proxy-dns (см. final ниже).
  if (!routeAll) {
    if (proxyProcessNames.length > 0) {
      dnsRules.push({ process_name: proxyProcessNames, action: 'route', server: 'proxy-dns' });
    }
    if (proxyProcessPaths.length > 0) {
      dnsRules.push({ process_path: proxyProcessPaths, action: 'route', server: 'proxy-dns' });
    }
    if (processPathRegexes.length > 0) {
      dnsRules.push({ process_path_regex: processPathRegexes, action: 'route', server: 'proxy-dns' });
    }
  }

  return {
    log: {
      level: logLevel,
      timestamp: true,
    },
    dns: {
      servers: [
        // Через VPN — Cloudflare. Используется для трафика, идущего через прокси.
        { tag: 'proxy-dns', type: 'udp', server: '1.1.1.1', detour: 'proxy' },
        // DNS для direct-трафика (весь не-VPN трафик + резолв VLESS-сервера).
        // DoH через IP обходит UDP/53 блокировки провайдера.
        // Сертификат Cloudflare содержит SAN 1.1.1.1 — без bootstrap-резолва.
        { tag: 'local-dns', type: 'https', server: '1.1.1.1', path: '/dns-query', detour: 'direct' },
      ],
      rules: dnsRules,
      // В full-tunnel DNS тоже через VPN — иначе утечка через провайдера.
      final: routeAll ? 'proxy-dns' : 'local-dns',
      // ipv4_only сокращает количество DNS-запросов вдвое (нет AAAA) и
      // снимает кучу "exchange failed for ... IN AAAA" в логах, поскольку
      // IPv6 поверх VLESS у нас всё равно нормально не работает.
      strategy: 'ipv4_only',
      disable_cache: false,
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        interface_name: 'swanray-tun',
        address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
        mtu: 9000,
        auto_route: true,
        strict_route: true,
        stack: 'system',
      },
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: mixedPort,
      },
    ],
    outbounds: [
      { ...proxyOutbound, domain_resolver: 'local-dns' },
      { type: 'direct', tag: 'direct', domain_resolver: 'local-dns' },
    ],
    route: {
      rules: routeRules,
      auto_detect_interface: true,
      // Явно включаем поиск процесса по соединениям. Без этого флага
      // process_name / process_path могут не матчиться, и трафик уходит в final.
      find_process: true,
      default_domain_resolver: 'local-dns',
      final: routeAll ? 'proxy' : 'direct',
    },
    experimental: {
      cache_file: { enabled: true },
    },
  };
}

module.exports = { buildSingBoxConfig, buildVlessOutbound };
