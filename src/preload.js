const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    runAnalysis: (peFilePath, expectedHash) => ipcRenderer.invoke('run-analysis', peFilePath, expectedHash),
});
