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
 * @param {object} options
 * @param {object} options.vless - объект из parseVlessUrl
 * @param {string[]} options.bypassPrograms - массив исполняемых файлов (имена exe), которые НЕ должны идти через VPN
 * @param {number} [options.mixedPort=2080] - порт для локального HTTP/SOCKS прокси
 * @param {string} [options.logLevel='info']
 */
function buildSingBoxConfig(options) {
  const {
    vless,
    bypassPrograms = [],
    mixedPort = 2080,
    logLevel = 'warn',
  } = options;

  const proxyOutbound = buildVlessOutbound(vless);

  const normalizedBypass = bypassPrograms
    .map((p) => (typeof p === 'string' ? p.trim() : ''))
    .filter(Boolean)
    .map((p) => {
      // Извлекаем только имя файла, без пути.
      const base = path.basename(p);
      return base.toLowerCase();
    });

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

  if (normalizedBypass.length > 0) {
    routeRules.push({
      process_name: normalizedBypass,
      outbound: 'direct',
    });
  }

  // Определяем, является ли vless.host доменом (а не IP). Если домен —
  // нужно жёстко резолвить его через local-dns, иначе ещё один loop:
  // proxy outbound для коннекта к серверу запросит резолв через final=proxy-dns.
  const isIpHost =
    !!vless.host && (/^[0-9.]+$/.test(vless.host) || /^\[?[0-9a-f:]+\]?$/i.test(vless.host));
  const dnsRules = [];
  if (!isIpHost && vless.host) {
    dnsRules.push({ domain: [vless.host], server: 'local-dns' });
  }
  if (vless.sni && vless.sni !== vless.host && !isIpHost) {
    dnsRules.push({ domain: [vless.sni], server: 'local-dns' });
  }
  // DNS-запросы программ-исключений тоже должны идти напрямую (через 8.8.8.8),
  // а не через proxy-dns, иначе игра ходит за IP через VPN и пинг растёт.
  if (normalizedBypass.length > 0) {
    dnsRules.push({ process_name: normalizedBypass, server: 'local-dns' });
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
        // DNS для direct-трафика (bypass-программы + резолв VLESS-сервера).
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
      final: 'proxy-dns',
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
      final: 'proxy',
    },
    experimental: {
      cache_file: { enabled: true },
    },
  };
}

module.exports = { buildSingBoxConfig, buildVlessOutbound };
