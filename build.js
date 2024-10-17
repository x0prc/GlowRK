const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Define paths
const reactAppPath = path.join(__dirname, 'src', 'renderer'); 
const buildPath = path.join(reactAppPath, 'build'); 


function buildReactApp() {
    return new Promise((resolve, reject) => {
        console.log('Building React app...');
        exec('npm run build', { cwd: reactAppPath }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error building React app: ${stderr}`);
                return reject(error);
            }
            console.log(stdout);
            resolve();
        });
    });
}


function startElectronApp() {
    return new Promise((resolve, reject) => {
        console.log('Starting Electron app...');
        exec('electron .', { cwd: __dirname }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error starting Electron app: ${stderr}`);
                return reject(error);
            }
            console.log(stdout);
            resolve();
        });
    });
}


async function main() {
    try {
        await buildReactApp();
        
        
        if (!fs.existsSync(buildPath)) {
            throw new Error('Build directory does not exist. Please check if the React app built successfully.');
        }

        await startElectronApp();
    } catch (error) {
        console.error(`Failed to build and start the application: ${error.message}`);
    }
}


main();
