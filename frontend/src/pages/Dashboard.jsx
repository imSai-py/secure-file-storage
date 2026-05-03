/**
 * Secure File Storage — Dashboard Page
 * Main file management interface with upload, download, and delete.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { useAuth } from '../context/AuthContext';
import { filesAPI } from '../services/api';
import {
  HiCloudArrowUp, HiDocumentText, HiPhoto, HiArchiveBox,
  HiArrowDownTray, HiTrash, HiShieldCheck, HiFolder,
  HiArrowRightOnRectangle, HiDocument, HiLockClosed,
  HiClock, HiServer
} from 'react-icons/hi2';
import toast from 'react-hot-toast';

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

function getFileIcon(mimeType) {
  if (mimeType?.startsWith('image/')) return { icon: <HiPhoto />, className: 'file-icon-img' };
  if (mimeType?.includes('pdf')) return { icon: <HiDocumentText />, className: 'file-icon-pdf' };
  if (mimeType?.includes('word') || mimeType?.includes('document')) return { icon: <HiDocumentText />, className: 'file-icon-doc' };
  if (mimeType?.includes('zip') || mimeType?.includes('archive')) return { icon: <HiArchiveBox />, className: 'file-icon-default' };
  return { icon: <HiDocument />, className: 'file-icon-default' };
}

export default function Dashboard() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const fetchFiles = useCallback(async () => {
    try {
      const { data } = await filesAPI.list();
      setFiles(data.data || []);
    } catch (err) {
      if (err.response?.status === 401) {
        navigate('/login');
      } else {
        toast.error('Failed to load files');
      }
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => { fetchFiles(); }, [fetchFiles]);

  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;
    const file = acceptedFiles[0];

    setUploading(true);
    setUploadProgress(0);

    try {
      await filesAPI.upload(file, (progressEvent) => {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setUploadProgress(percent);
      });
      toast.success(`${file.name} encrypted & uploaded!`);
      fetchFiles();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  }, [fetchFiles]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024,
  });

  const handleDownload = async (file) => {
    try {
      toast.loading('Decrypting file...', { id: 'download' });
      const response = await filesAPI.download(file.id);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', file.originalName);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('File decrypted & downloaded!', { id: 'download' });
    } catch {
      toast.error('Download failed', { id: 'download' });
    }
  };

  const handleDelete = async (file) => {
    if (!window.confirm(`Permanently delete "${file.originalName}"? This cannot be undone.`)) return;
    try {
      await filesAPI.delete(file.id);
      toast.success('File permanently deleted');
      setFiles((prev) => prev.filter((f) => f.id !== file.id));
    } catch {
      toast.error('Delete failed');
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const totalSize = files.reduce((sum, f) => sum + (f.fileSize || 0), 0);

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon"><HiShieldCheck /></div>
          <span className="sidebar-logo-text">SecureVault</span>
        </div>

        <nav className="sidebar-nav">
          <a href="#" className="nav-link active">
            <HiFolder /> My Files
          </a>
        </nav>

        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem', marginTop: 'auto' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            Signed in as
          </div>
          <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '1rem', wordBreak: 'break-all' }}>
            {user?.email}
          </div>
          <button onClick={handleLogout} className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }}>
            <HiArrowRightOnRectangle /> Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <div className="page-header animate-fadeIn">
          <div>
            <h1 className="page-title">My Secure Files</h1>
            <p className="page-subtitle">All files are encrypted with AES-256-GCM</p>
          </div>
          <span className="encryption-badge">
            <HiLockClosed style={{ fontSize: '0.7rem' }} /> End-to-End Encrypted
          </span>
        </div>

        {/* Stats */}
        <div className="stats-grid animate-fadeInUp">
          <div className="glass-card stat-card">
            <div className="stat-label"><HiDocument style={{ marginRight: '4px' }} /> Total Files</div>
            <div className="stat-value">{files.length}</div>
          </div>
          <div className="glass-card stat-card">
            <div className="stat-label"><HiServer style={{ marginRight: '4px' }} /> Storage Used</div>
            <div className="stat-value">{formatFileSize(totalSize)}</div>
          </div>
          <div className="glass-card stat-card">
            <div className="stat-label"><HiShieldCheck style={{ marginRight: '4px' }} /> Encryption</div>
            <div className="stat-value" style={{ fontSize: '1.25rem' }}>AES-256</div>
          </div>
          <div className="glass-card stat-card">
            <div className="stat-label"><HiClock style={{ marginRight: '4px' }} /> Last Upload</div>
            <div className="stat-value" style={{ fontSize: '1rem' }}>
              {files.length > 0 ? formatDate(files[0].createdAt) : 'N/A'}
            </div>
          </div>
        </div>

        {/* Upload Zone */}
        <div className="animate-fadeInUp" style={{ animationDelay: '100ms' }}>
          <div {...getRootProps()} className={`dropzone ${isDragActive ? 'dropzone-active' : ''}`}
            style={{ marginBottom: '2rem' }}>
            <input {...getInputProps()} />
            {uploading ? (
              <div>
                <div className="spinner" style={{ width: '40px', height: '40px', margin: '0 auto 1rem', borderWidth: '3px' }} />
                <p style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Encrypting & Uploading...</p>
                <div className="progress-bar" style={{ maxWidth: '300px', margin: '0 auto' }}>
                  <div className="progress-fill" style={{ width: `${uploadProgress}%` }} />
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>{uploadProgress}%</p>
              </div>
            ) : (
              <div>
                <HiCloudArrowUp style={{
                  fontSize: '3rem', color: isDragActive ? 'var(--accent-primary)' : 'var(--text-muted)',
                  marginBottom: '0.75rem', transition: 'color 200ms'
                }} />
                <p style={{ fontWeight: 600, marginBottom: '0.25rem' }}>
                  {isDragActive ? 'Drop file to encrypt & upload' : 'Drag & drop a file here'}
                </p>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  or click to browse • Max 50MB • PDF, DOCX, PNG, JPG, TXT, ZIP
                </p>
              </div>
            )}
          </div>
        </div>

        {/* File List */}
        <div className="animate-fadeInUp" style={{ animationDelay: '200ms' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <HiFolder style={{ color: 'var(--accent-primary)' }} />
            Encrypted Files
            <span className="badge badge-success" style={{ marginLeft: '0.5rem' }}>{files.length}</span>
          </h3>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '3rem' }}>
              <div className="spinner" style={{ width: '40px', height: '40px', margin: '0 auto', borderWidth: '3px' }} />
            </div>
          ) : files.length === 0 ? (
            <div className="glass-card" style={{ textAlign: 'center', padding: '3rem' }}>
              <HiShieldCheck style={{ fontSize: '3rem', color: 'var(--text-muted)', marginBottom: '1rem' }} />
              <p style={{ fontWeight: 600, marginBottom: '0.25rem' }}>No files yet</p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Upload your first file to encrypt and store it securely.</p>
            </div>
          ) : (
            <div className="stagger-children" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {files.map((file) => {
                const { icon, className } = getFileIcon(file.mimeType);
                return (
                  <div key={file.id} className="file-item animate-fadeInUp">
                    <div className={`file-icon ${className}`}>{icon}</div>
                    <div className="file-info">
                      <div className="file-name">{file.originalName}</div>
                      <div className="file-meta">
                        {formatFileSize(file.fileSize)} • {formatDate(file.createdAt)}
                        <span style={{ marginLeft: '0.5rem' }} className="encryption-badge">
                          <HiLockClosed style={{ fontSize: '0.6rem' }} /> Encrypted
                        </span>
                      </div>
                    </div>
                    <div className="file-actions">
                      <button className="btn btn-secondary btn-icon" title="Download & Decrypt"
                        onClick={() => handleDownload(file)}>
                        <HiArrowDownTray />
                      </button>
                      <button className="btn btn-danger btn-icon" title="Delete Permanently"
                        onClick={() => handleDelete(file)}>
                        <HiTrash />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
