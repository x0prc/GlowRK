document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const peFilePath = document.getElementById('peFilePath').value;
    const expectedHash = document.getElementById('expectedHash').value;
    
    try {
        const result = await window.api.runAnalysis(peFilePath, expectedHash);
        document.getElementById('output').innerText = result;
    } catch (error) {
        document.getElementById('output').innerText = error;
    }
});
