import React from 'react';
import { Link } from 'react-router-dom';

const Dashboard = () => {
    return (
        <div className="dashboard">
            <h2>Welcome to GlowRK</h2>
            <p>Select an option below:</p>
            <ul>
                <li><Link to="/upload">Upload Memory Dump</Link></li>
                <li><Link to="/analysis">View Analysis Results</Link></li>
            </ul>
        </div>
    );
};

export default Dashboard;
