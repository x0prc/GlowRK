const { app, BrowserWindow } = require('electron');
const path = require('path');

let mainWindow;

async function createWindow() {
    
    const isDev = (await import('electron-is-dev')).default;

   
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),             
            contextIsolation: true,
            enableRemoteModule: false,          
            nodeIntegration: false        }
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

// Handle app lifecycle events
app.on('ready', createWindow);
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit(); // Quit app when all windows are closed (except on macOS)
    }
});
app.on('activate', () => {
    if (mainWindow === null) {
        createWindow(); // Recreate window on macOS if it's closed and activated again
    }
});
