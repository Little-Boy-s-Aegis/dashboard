import { useState, useEffect } from 'react';
import { Shield, KeyRound, RefreshCw, Eye } from 'lucide-react';

interface Props {
  onLoginSuccess: (username: string) => void;
}

export default function Login({ onLoginSuccess }: Props) {
  const [uid, setUid] = useState('');
  const [operatorName, setOperatorName] = useState('');
  const [token, setToken] = useState('');
  const [step, setStep] = useState<1 | 2>(1); // 1 = Request token, 2 = Verify token
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [otpExpiry, setOtpExpiry] = useState<Date | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);

  useEffect(() => {
    if (!otpExpiry) return;
    const timer = setInterval(() => {
      const left = Math.max(0, Math.round((otpExpiry.getTime() - new Date().getTime()) / 1000));
      setSecondsLeft(left);
      if (left === 0) {
        setOtpExpiry(null);
        setErrorMsg('One-Time Token has expired. Please request a new one.');
        setStep(1);
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [otpExpiry]);

  const handleRequestToken = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanUid = uid.trim();
    if (!cleanUid) {
      setErrorMsg('Operator UID is required.');
      return;
    }
    // Validation check: must be exactly 5 digits
    if (!/^\d{5}$/.test(cleanUid)) {
      setErrorMsg('Operator UID must be exactly 5 digits.');
      return;
    }

    setErrorMsg('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/request-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: cleanUid })
      });
      const data = await res.json();
      if (res.ok) {
        // Backend no longer returns username/expiry to prevent enumeration (S-02 fix)
        setOperatorName('Operator');
        setOtpExpiry(new Date(Date.now() + 5 * 60 * 1000)); // 5-minute client-side countdown
        setStep(2);
      } else {
        setErrorMsg(data.error || 'Failed to request login token.');
      }
    } catch {
      setErrorMsg('Unable to connect to security authentication server.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) {
      setErrorMsg('SHA-256 Token is required.');
      return;
    }
    setErrorMsg('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: uid.trim(), token: token.trim() })
      });
      const data = await res.json();
      if (res.ok) {
        setOtpExpiry(null);
        onLoginSuccess(data.username);
      } else {
        setErrorMsg(data.error || 'Invalid credentials.');
      }
    } catch {
      setErrorMsg('Authentication error. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: 'flex', justifyContent: 'center', alignItems: 'center',
      minHeight: '100vh', background: 'var(--bg-canvas)', padding: 20
    }}>
      <div style={{
        width: '100%', maxWidth: 420, display: 'flex', flexDirection: 'column', gap: 16,
        animation: 'fadeInUp 0.3s ease-out'
      }}>
        
        {/* Splunk-Style Login Box */}
        <div className="glass-panel" style={{ padding: '32px 28px', border: '1px solid var(--border-1)', position: 'relative' }}>
          {/* Top Brand Stripe */}
          <div style={{
            position: 'absolute', top: 0, left: 0, right: 0, height: 3,
            background: 'var(--accent)', borderRadius: '4px 4px 0 0'
          }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center', marginBottom: 24 }}>
            <Shield size={24} style={{ color: 'var(--accent)' }} />
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '0.04em', margin: 0, color: 'var(--text-0)' }}>
              AEGIS <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>SOC</span>
            </h1>
          </div>

          <p style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-2)', marginBottom: 24, marginTop: -14 }}>
            Enterprise Threat Detection & Incident Response Platform
          </p>

          {step === 1 ? (
            <form onSubmit={handleRequestToken} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Operator UID
                </label>
                <input
                  type="text"
                  className="search-input"
                  value={uid}
                  onChange={e => setUid(e.target.value.replace(/\D/g, '').slice(0, 5))}
                  placeholder="e.g. 10001, 10002"
                  style={{ width: '100%', height: 36, fontSize: '0.9rem', letterSpacing: '0.05em' }}
                  disabled={loading}
                  autoFocus
                />
              </div>

              <button className="btn btn-primary" type="submit" disabled={loading} style={{
                height: 38, fontSize: '0.85rem', fontWeight: 600, display: 'flex', justifyContent: 'center',
                alignItems: 'center', gap: 6, width: '100%', marginTop: 6
              }}>
                {loading ? <RefreshCw size={14} className="spin" /> : <KeyRound size={14} />}
                Request Login Token
              </button>
            </form>
          ) : (
            <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', textTransform: 'uppercase' }}>Operator Identity</span>
                <strong style={{ color: 'var(--text-0)', fontSize: '0.88rem' }}>UID {uid} ({operatorName})</strong>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    SHA-256 Token
                  </label>
                  <span style={{ fontSize: '0.65rem', color: 'var(--high)', fontFamily: "'IBM Plex Mono', monospace" }}>
                    Expires in {secondsLeft}s
                  </span>
                </div>
                <input
                  type="text"
                  className="search-input"
                  value={token}
                  onChange={e => setToken(e.target.value)}
                  placeholder="Paste 64-character SHA-256 Token"
                  style={{ width: '100%', height: 36, fontSize: '0.78rem', fontFamily: "'IBM Plex Mono', monospace", textAlign: 'center' }}
                  disabled={loading}
                  autoFocus
                />
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-outline" type="button" onClick={() => { setStep(1); setToken(''); }} style={{ flex: 1, height: 38 }}>
                  Back
                </button>
                <button className="btn btn-primary" type="submit" disabled={loading} style={{
                  flex: 2, height: 38, fontSize: '0.85rem', fontWeight: 600, display: 'flex', justifyContent: 'center',
                  alignItems: 'center', gap: 6
                }}>
                  {loading ? <RefreshCw size={14} className="spin" /> : <Eye size={14} />}
                  Verify & Login
                </button>
              </div>
            </form>
          )}

          {errorMsg && (
            <div style={{
              marginTop: 16, padding: '10px 12px', background: 'var(--critical-bg)',
              border: '1px solid rgba(217,63,60,0.2)', fontSize: '0.78rem', color: 'var(--critical-dim)',
              borderRadius: 'var(--r-xs)', animation: 'fadeInUp 0.15s ease-out'
            }}>
              {errorMsg}
            </div>
          )}
        </div>

        <div style={{ textAlign: 'center', fontSize: '0.68rem', color: 'var(--text-3)', marginTop: 8 }}>
          Aegis Platform v2.4.1 · Protected by 8-Hour Session Expiry
        </div>
      </div>
    </div>
  );
}
