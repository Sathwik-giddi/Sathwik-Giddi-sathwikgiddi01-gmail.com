import React from 'react';
import { createRoot } from 'react-dom/client';

import './styles.css';
import { App } from './App.jsx';

// The whole console. No router library: there are two routes, one of which (`/invite/:token`) is
// matched inside App before the shell is ever considered, and the other of which is "not an invite".
// A routing dependency for that would be more code than the routing.
createRoot(document.getElementById('root')).render(<App />);
