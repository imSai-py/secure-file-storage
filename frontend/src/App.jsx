/**
 * Secure File Storage — App Entry Point
 * Sets up routing, auth protection, and global providers.
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="spinner" style={{ width: '40px', height: '40px', borderWidth: '3px' }} />
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function PublicRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="spinner" style={{ width: '40px', height: '40px', borderWidth: '3px' }} />
      </div>
    );
  }

  return isAuthenticated ? <Navigate to="/dashboard" replace /> : children;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 3000,
            className: 'toast-custom',
            style: {
              background: '#111827',
              color: '#f0f4ff',
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: '12px',
            },
          }}
        />
      </AuthProvider>
    </BrowserRouter>
  );
}
