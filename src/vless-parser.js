'use strict';

/**
 * Парсер VLESS URL формата:
 *   vless://UUID@HOST:PORT?param=value&...#remark
 *
 * Поддерживаемые параметры:
 *   type       - транспорт: tcp | ws | grpc | http | quic
 *   security   - tls | reality | none
 *   encryption - обычно "none"
 *   flow       - xtls-rprx-vision и т.п.
 *   sni        - Server Name Indication
 *   alpn       - h2,http/1.1
 *   fp         - fingerprint утилизации TLS (chrome, firefox, ...)
 *   pbk        - публичный ключ для Reality
 *   sid        - short id для Reality
 *   spx        - spider X path для Reality
 *   path       - путь для ws/h2
 *   host       - HTTP Host header для ws
 *   serviceName- имя сервиса для grpc
 *   headerType - тип заголовка (http и др.)
 */
function parseVlessUrl(rawUrl) {
  if (typeof rawUrl !== 'string') {
    throw new Error('VLESS URL должен быть строкой');
  }

  const trimmed = rawUrl.trim();
  if (!trimmed.toLowerCase().startsWith('vless://')) {
    throw new Error('URL должен начинаться с vless://');
  }

  // Стандартный URL не понимает "vless://", поэтому подменяем схему.
  let url;
  try {
    url = new URL('http://' + trimmed.slice('vless://'.length));
  } catch (e) {
    throw new Error('Невалидный VLESS URL: ' + e.message);
  }

  const uuid = decodeURIComponent(url.username || '');
  if (!uuid) {
    throw new Error('В VLESS URL отсутствует UUID');
  }

  const host = url.hostname;
  if (!host) {
    throw new Error('В VLESS URL отсутствует адрес сервера');
  }

  const port = parseInt(url.port, 10);
  if (!port || port < 1 || port > 65535) {
    throw new Error('В VLESS URL некорректный порт');
  }

  const params = {};
  url.searchParams.forEach((value, key) => {
    params[key.toLowerCase()] = value;
  });

  const remark = url.hash ? decodeURIComponent(url.hash.slice(1)) : '';

  return {
    raw: trimmed,
    uuid,
    host,
    port,
    remark,
    transport: (params.type || 'tcp').toLowerCase(),
    security: (params.security || 'none').toLowerCase(),
    encryption: params.encryption || 'none',
    flow: params.flow || '',
    sni: params.sni || '',
    alpn: params.alpn ? params.alpn.split(',').map((s) => s.trim()).filter(Boolean) : [],
    fingerprint: params.fp || '',
    realityPublicKey: params.pbk || '',
    realityShortId: params.sid || '',
    realitySpiderX: params.spx || '',
    wsPath: params.path || '',
    wsHost: params.host || '',
    grpcServiceName: params.servicename || '',
    headerType: params.headertype || '',
  };
}

module.exports = { parseVlessUrl };
