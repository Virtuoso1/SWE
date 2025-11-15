import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './modules/auth/AuthProvider';
import './styles/global.css';
import './styles/layouts.css';
import './styles/form-styles.css';
import './styles/table-styles.css';
import './styles/card-styles.css';
import './styles/page-styles.css';
import './styles/dark-theme.css';

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);