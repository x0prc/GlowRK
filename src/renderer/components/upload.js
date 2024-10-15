import React, { useState } from 'react';

const Upload = () => {
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState('');

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleUpload = async () => {
        if (!file) {
            setMessage('Please select a file to upload.');
            return;
        }

        const formData = new FormData();
        formData.append('memoryDump', file);

        try {
            const response = await fetch('http://localhost:5000/upload', { // Adjust URL as needed
                method: 'POST',
                body: formData,
            });

            if (response.ok) {
                setMessage('File uploaded successfully!');
            } else {
                setMessage('Error uploading file.');
            }
        } catch (error) {
            console.error(error);
            setMessage('Error uploading file.');
        }
    };

    return (
        <div className="upload">
            <h2>Upload Memory Dump</h2>
            <input type="file" onChange={handleFileChange} />
            <button onClick={handleUpload}>Upload</button>
            {message && <p>{message}</p>}
        </div>
    );
};

export default Upload;
