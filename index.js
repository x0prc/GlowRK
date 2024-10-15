
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const isDev = require('electron-is-dev');

function createWindow() {
  
    const mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'), 
            contextIsolation: true, 
            enableRemoteModule: false, 
            nodeIntegration: false 
        }
    });

        const startUrl = isDev 
        ? 'http://localhost:3000' 
        : `file://${path.join(__dirname, '../build/index.html')}`; 

    mainWindow.loadURL(startUrl);

    
    if (isDev) {
        mainWindow.webContents.openDevTools();
    }

        mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.on('ready', createWindow);
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit(); 
    }
});
app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();     }
});

ipcMain.on('some-event', (event, arg) => {
    console.log(arg);
    event.reply('some-reply', 'Response from main process'); 
});
