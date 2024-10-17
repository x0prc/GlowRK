import React, { useEffect, useState } from 'react';

const Analysis = () => {
    const [results, setResults] = useState(null);
    
    useEffect(() => {
        const fetchResults = async () => {
            try {
                const response = await fetch('http://localhost:5000/results'); // Adjust URL as needed
                const data = await response.json();
                setResults(data);
            } catch (error) {
                console.error(error);
                setResults({ error: 'Failed to fetch results.' });
            }
        };

        fetchResults();
    }, []);

    return (
        <div className="analysis">
            <h2>Analysis Results</h2>
            {results ? (
                results.error ? (
                    <p>{results.error}</p>
                ) : (
                    <pre>{JSON.stringify(results, null, 2)}</pre>
                )
            ) : (
                <p>Loading...</p>
            )}
        </div>
    );
};

export default Analysis;
