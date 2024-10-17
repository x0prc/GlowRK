import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Analysis from './components/Analysis';
import Upload from './components/Upload';
import './styles.css';

const App = () => {
    return (
        <Router>
            <div className="app">
                <h1>GlowRK</h1>
                <Switch>
                    <Route path="/" exact component={Dashboard} />
                    <Route path="/upload" component={Upload} />
                    <Route path="/analysis" component={Analysis} />
                </Switch>
            </div>
        </Router>
    );
};

export default App;
