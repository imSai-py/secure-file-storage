/**
 * Secure File Storage — Register Page
 */

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { HiShieldCheck, HiEnvelope, HiLockClosed, HiEye, HiEyeSlash } from 'react-icons/hi2';
import toast from 'react-hot-toast';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const passwordChecks = [
    { label: 'At least 12 characters', valid: password.length >= 12 },
    { label: 'One uppercase letter', valid: /[A-Z]/.test(password) },
    { label: 'One lowercase letter', valid: /[a-z]/.test(password) },
    { label: 'One number', valid: /[0-9]/.test(password) },
    { label: 'One special character', valid: /[^A-Za-z0-9]/.test(password) },
  ];

  const allValid = passwordChecks.every((c) => c.valid) && password === confirmPassword && confirmPassword.length > 0;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (!passwordChecks.every((c) => c.valid)) {
      toast.error('Password does not meet requirements');
      return;
    }
    setLoading(true);
    try {
      await register(email, password);
      toast.success('Account created! Please sign in.');
      navigate('/login');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card glass-card animate-fadeInUp">
        <div className="auth-header">
          <div className="auth-icon" style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}>
            <HiShieldCheck />
          </div>
          <h1 style={{ fontSize: '1.5rem' }}>Create Account</h1>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
            Start securing your files today
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="input-group">
            <label htmlFor="register-email">Email Address</label>
            <div style={{ position: 'relative' }}>
              <HiEnvelope style={{
                position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                color: 'var(--text-muted)', fontSize: '1.1rem'
              }} />
              <input id="register-email" type="email" className="input-field"
                style={{ paddingLeft: '2.5rem', width: '100%' }}
                placeholder="you@example.com" value={email}
                onChange={(e) => setEmail(e.target.value)} required />
            </div>
          </div>

          <div className="input-group">
            <label htmlFor="register-password">Password</label>
            <div style={{ position: 'relative' }}>
              <HiLockClosed style={{
                position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                color: 'var(--text-muted)', fontSize: '1.1rem'
              }} />
              <input id="register-password" type={showPassword ? 'text' : 'password'}
                className="input-field"
                style={{ paddingLeft: '2.5rem', paddingRight: '2.5rem', width: '100%' }}
                placeholder="Create a strong password" value={password}
                onChange={(e) => setPassword(e.target.value)} required />
              <button type="button" onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer',
                  fontSize: '1.1rem', padding: 0
                }}>
                {showPassword ? <HiEyeSlash /> : <HiEye />}
              </button>
            </div>
          </div>

          {/* Password strength indicators */}
          {password.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              {passwordChecks.map((check, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem',
                  fontSize: '0.8rem', color: check.valid ? 'var(--success)' : 'var(--text-muted)'
                }}>
                  <span style={{
                    width: '6px', height: '6px', borderRadius: '50%',
                    background: check.valid ? 'var(--success)' : 'var(--text-muted)',
                    transition: 'background 200ms'
                  }} />
                  {check.label}
                </div>
              ))}
            </div>
          )}

          <div className="input-group">
            <label htmlFor="register-confirm">Confirm Password</label>
            <input id="register-confirm" type="password" className="input-field"
              style={{ width: '100%' }} placeholder="Confirm your password"
              value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
            {confirmPassword.length > 0 && password !== confirmPassword && (
              <span style={{ fontSize: '0.8rem', color: 'var(--danger)' }}>Passwords do not match</span>
            )}
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading || !allValid}
            style={{ width: '100%', marginTop: '0.5rem', padding: '0.875rem' }}>
            {loading ? <span className="spinner" /> : 'Create Secure Account'}
          </button>
        </form>

        <div className="auth-footer">
          Already have an account?{' '}
          <Link to="/login" style={{ fontWeight: 600 }}>Sign in</Link>
        </div>
      </div>
    </div>
  );
}
