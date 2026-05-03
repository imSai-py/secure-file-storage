/**
 * Secure File Storage — Login Page
 */

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { HiLockClosed, HiEnvelope, HiEye, HiEyeSlash } from 'react-icons/hi2';
import toast from 'react-hot-toast';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(email, password);
      toast.success('Welcome back!');
      navigate('/dashboard');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card glass-card animate-fadeInUp">
        <div className="auth-header">
          <div className="auth-icon">
            <HiLockClosed />
          </div>
          <h1 style={{ fontSize: '1.5rem' }}>Welcome Back</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
            Sign in to your secure vault
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="input-group">
            <label htmlFor="login-email">Email Address</label>
            <div style={{ position: 'relative' }}>
              <HiEnvelope style={{
                position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                color: 'var(--text-muted)', fontSize: '1.1rem'
              }} />
              <input
                id="login-email"
                type="email"
                className="input-field"
                style={{ paddingLeft: '2.5rem', width: '100%' }}
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="input-group">
            <label htmlFor="login-password">Password</label>
            <div style={{ position: 'relative' }}>
              <HiLockClosed style={{
                position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                color: 'var(--text-muted)', fontSize: '1.1rem'
              }} />
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                className="input-field"
                style={{ paddingLeft: '2.5rem', paddingRight: '2.5rem', width: '100%' }}
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer',
                  fontSize: '1.1rem', padding: 0
                }}
              >
                {showPassword ? <HiEyeSlash /> : <HiEye />}
              </button>
            </div>
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading}
            style={{ width: '100%', marginTop: '0.5rem', padding: '0.875rem' }}>
            {loading ? <span className="spinner" /> : 'Sign In'}
          </button>
        </form>

        <div className="auth-footer">
          Don't have an account?{' '}
          <Link to="/register" style={{ fontWeight: 600 }}>Create one</Link>
        </div>

        <div style={{ textAlign: 'center', marginTop: '1.25rem' }}>
          <span className="encryption-badge">
            <HiLockClosed style={{ fontSize: '0.7rem' }} />
            AES-256-GCM Encrypted
          </span>
        </div>
      </div>
    </div>
  );
}
