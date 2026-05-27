'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (partial) => ipcRenderer.invoke('settings:set', partial),

  getStatus: () => ipcRenderer.invoke('vpn:status'),
  connect: (payload) => ipcRenderer.invoke('vpn:connect', payload),
  disconnect: () => ipcRenderer.invoke('vpn:disconnect'),

  pickExe: () => ipcRenderer.invoke('dialog:pick-exe'),
  openBinFolder: () => ipcRenderer.invoke('app:open-bin-folder'),
  getBinInfo: () => ipcRenderer.invoke('app:bin-info'),

  onLog: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('singbox:log', listener);
    return () => ipcRenderer.removeListener('singbox:log', listener);
  },
  onStatus: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('singbox:status', listener);
    return () => ipcRenderer.removeListener('singbox:status', listener);
  },
});
