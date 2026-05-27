'use strict';

const path = require('path');

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
 * Режим include-only (split tunneling наоборот): по умолчанию весь трафик
 * идёт напрямую, а через VPN направляются ТОЛЬКО указанные программы.
 *
 * @param {object} options
 * @param {object} options.vless - объект из parseVlessUrl
 * @param {Array<string|{name?:string, fullPath?:string}>} options.proxyPrograms -
 *   программы, трафик которых пойдёт ЧЕРЕЗ VPN. Можно передавать просто имена
 *   ("Telegram.exe") либо объекты {name, fullPath} — fullPath даёт более
 *   надёжный матч и нечувствителен к регистру и наличию одноимённых exe.
 * @param {boolean} [options.excludeRu=false] - если true, .ru и .рф домены
 *   идут напрямую (direct), даже если программа в списке proxyPrograms.
 * @param {number} [options.mixedPort=2080] - порт для локального HTTP/SOCKS прокси
 * @param {string} [options.logLevel='info']
 */
function buildSingBoxConfig(options) {
  const {
    vless,
    proxyPrograms = [],
    excludeRu = false,
    mixedPort = 2080,
    logLevel = 'warn',
  } = options;

  const proxyOutbound = buildVlessOutbound(vless);

  // Нормализуем список: собираем уникальные basenames И уникальные full paths.
  // process_name в sing-box на Windows ищется регистронезависимо, поэтому
  // не лоумим — отдаём как есть. Дубликаты разного регистра отсеиваем по lowercase.
  const seenNames = new Set();
  const proxyProcessNames = [];
  const proxyProcessPaths = [];
  for (const raw of proxyPrograms) {
    if (!raw) continue;
    const obj = typeof raw === 'string' ? { name: raw } : raw;
    let name = (obj.name || '').trim();
    const fullPath = (obj.fullPath || '').trim();
    if (!name && fullPath) name = path.basename(fullPath);
    if (!name) continue;
    name = path.basename(name);
    const key = name.toLowerCase();
    if (!seenNames.has(key)) {
      seenNames.add(key);
      proxyProcessNames.push(name);
    }
    if (fullPath && !proxyProcessPaths.includes(fullPath)) {
      proxyProcessPaths.push(fullPath);
    }
  }

  // ВАЖНО: правила обрабатываются сверху вниз, первое совпавшее побеждает.
  // Порядок критичен — собственные DNS-запросы sing-box должны уходить direct
  // ДО общего hijack-dns правила, иначе они зацикливаются: sing-box → TUN →
  // hijack → DNS-резолвер → upstream через direct → пакет в TUN → hijack...
  const routeRules = [
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

  // 4. Российские домены (.ru / .рф) — direct ДО proxy-правил, чтобы даже
  //    программы из списка ходили на них напрямую. Требует sniff: true на TUN.
  //    Опирается на TLS SNI / HTTP Host из захваченных пакетов; для соединений
  //    по чистому IP без домена не сработает (но для браузеров — почти всегда).
  if (excludeRu) {
    routeRules.push({
      domain_suffix: ['.ru', '.рф'],
      outbound: 'direct',
    });
  }

  // 5. Выбранные программы — через VPN. Всё остальное упадёт в final=direct.
  //    Делаем ДВА правила: по process_name (если пользователь добавил вручную
  //    без пути) и по process_path (если файл выбран через диалог) — последнее
  //    надёжнее, т.к. process_name на некоторых стэках/версиях sing-box может
  //    не определяться для всех TCP-соединений (см. issue #2823 sing-box).
  if (proxyProcessNames.length > 0) {
    routeRules.push({ process_name: proxyProcessNames, outbound: 'proxy' });
  }
  if (proxyProcessPaths.length > 0) {
    routeRules.push({ process_path: proxyProcessPaths, outbound: 'proxy' });
  }

  // Определяем, является ли vless.host доменом (а не IP). Если домен —
  // нужно жёстко резолвить его через local-dns, иначе ещё один loop:
  // proxy outbound для коннекта к серверу запросит резолв через proxy-dns.
  const isIpHost =
    !!vless.host && (/^[0-9.]+$/.test(vless.host) || /^\[?[0-9a-f:]+\]?$/i.test(vless.host));
  const dnsRules = [];
  if (!isIpHost && vless.host) {
    dnsRules.push({ domain: [vless.host], server: 'local-dns' });
  }
  if (vless.sni && vless.sni !== vless.host && !isIpHost) {
    dnsRules.push({ domain: [vless.sni], server: 'local-dns' });
  }
  // Российские домены резолвим напрямую — чтобы не светить DNS-запросы
  // через VPN и получать "местный" IP CDN (Yandex/VK/Sber и пр.).
  if (excludeRu) {
    dnsRules.push({ domain_suffix: ['.ru', '.рф'], server: 'local-dns' });
  }
  // DNS-запросы программ, идущих через VPN, резолвим через proxy-dns,
  // чтобы DNS-лик не выдавал реального IP клиента DNS-серверу провайдера.
  // NB: на Windows DNS-запросы часто инициирует системный svchost (DNS Client),
  // а не само приложение — поэтому это правило срабатывает не всегда. Но если
  // приложение делает запрос напрямую (Telegram/Discord так и делают для своих
  // API-доменов), правило поможет.
  if (proxyProcessNames.length > 0) {
    dnsRules.push({ process_name: proxyProcessNames, server: 'proxy-dns' });
  }
  if (proxyProcessPaths.length > 0) {
    dnsRules.push({ process_path: proxyProcessPaths, server: 'proxy-dns' });
  }
  dnsRules.push({ outbound: 'direct', server: 'local-dns' });

  return {
    log: {
      level: logLevel,
      timestamp: true,
    },
    dns: {
      servers: [
        // Через VPN — Cloudflare. Используется для трафика, идущего через прокси.
        { tag: 'proxy-dns', address: '1.1.1.1', detour: 'proxy' },
        // DNS для direct-трафика (весь не-VPN трафик + резолв VLESS-сервера).
        // DoH через IP обходит UDP/53 блокировки провайдера (видны как
        // "dial udp 77.88.8.8:53: i/o timeout"). Сертификат Cloudflare
        // содержит SAN 1.1.1.1 — валидация TLS проходит без bootstrap-резолва.
        // Альтернативы при недоступности Cloudflare DoH:
        //   - 'tcp://77.88.8.8'              — TCP-DNS Яндекса (обходит UDP-блок)
        //   - 'https://77.88.8.8/dns-query'  — DoH Яндекса по IP
        //   - 'tls://1.1.1.1'                — DoT Cloudflare на порт 853
        // address: 'local' не используем — он завязан на системный резолвер,
        // который из-за auto_route TUN сам же и зацикливается.
        { tag: 'local-dns', address: 'https://1.1.1.1/dns-query', detour: 'direct' },
      ],
      rules: dnsRules,
      final: 'local-dns',
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
        sniff: true,
        sniff_override_destination: false,
      },
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: mixedPort,
        sniff: true,
      },
    ],
    outbounds: [
      proxyOutbound,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      rules: routeRules,
      auto_detect_interface: true,
      // Явно включаем поиск процесса по соединениям. Без этого флага
      // process_name / process_path могут не матчиться, и трафик уходит в final.
      find_process: true,
      final: 'direct',
    },
    experimental: {
      cache_file: { enabled: true },
    },
  };
}

module.exports = { buildSingBoxConfig, buildVlessOutbound };
