const { exec } = require('child_process');
const path = require('path');

function buildApp() {
    console.log('Building the App...');

    const command = 'npx electron-builder';

    exec(command, { cwd: path.join(__dirname) }, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error during build: ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`stderr: ${stderr}`);
            return;
        }
        console.log(`stdout: ${stdout}`);
        console.log('Build completed successfully!');
    });
}

buildApp();
