import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Login from './Login';

describe('Login Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test('renders step 1 input fields correctly', () => {
    render(<Login onLoginSuccess={vi.fn()} />);
    
    expect(screen.getByRole('heading', { name: /AEGIS/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/e.g. 10001, 10002/i)).toBeInTheDocument();
  });

  test('filters non-numeric input for operator UID', () => {
    render(<Login onLoginSuccess={vi.fn()} />);
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i) as HTMLInputElement;

    fireEvent.change(input, { target: { value: '12abc' } });
    expect(input.value).toBe('12');
  });

  test('limits operator UID to exactly 5 digits', () => {
    render(<Login onLoginSuccess={vi.fn()} />);
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i) as HTMLInputElement;

    fireEvent.change(input, { target: { value: '1234567' } });
    expect(input.value).toBe('12345');
  });

  test('handles successful token request flow', async () => {
    const mockResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response)
    );

    render(<Login onLoginSuccess={vi.fn()} />);
    
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i);
    fireEvent.change(input, { target: { value: '10001' } });
    
    const submitBtn = screen.getByRole('button', { name: /Request Login Token/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/auth/request-token', expect.any(Object));
      expect(screen.getByText(/Operator Identity/i)).toBeInTheDocument();
    });
  });

  test('displays error message on failed token request', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: false,
        json: () => Promise.resolve({ error: 'Invalid login request or account disabled' }),
      } as Response)
    );

    render(<Login onLoginSuccess={vi.fn()} />);
    
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i);
    fireEvent.change(input, { target: { value: '99999' } });
    
    const submitBtn = screen.getByRole('button', { name: /Request Login Token/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Invalid login request or account disabled/i)).toBeInTheDocument();
    });
  });

  test('displays connection error on failed request token fetch exception', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.reject(new Error('Network error'))
    );

    render(<Login onLoginSuccess={vi.fn()} />);
    
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i);
    fireEvent.change(input, { target: { value: '10001' } });
    
    const submitBtn = screen.getByRole('button', { name: /Request Login Token/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Unable to connect to security authentication server./i)).toBeInTheDocument();
    });
  });

  test('handles successful login verification flow (step 2)', async () => {
    // 1. Advance to step 2 first
    const mockRequestResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
      if (typeof url === 'string' && url.includes('/api/auth/request-token')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockRequestResponse),
        } as Response);
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ username: 'admin' }),
      } as Response);
    });

    const onLoginSuccess = vi.fn();
    render(<Login onLoginSuccess={onLoginSuccess} />);
    
    const input = screen.getByPlaceholderText(/e.g. 10001, 10002/i);
    fireEvent.change(input, { target: { value: '10001' } });
    fireEvent.click(screen.getByRole('button', { name: /Request Login Token/i }));

    await waitFor(() => {
      expect(screen.getByText(/Operator Identity/i)).toBeInTheDocument();
    });

    // 2. Perform step 2 login
    const tokenInput = screen.getByPlaceholderText(/Paste 64-character/i);
    fireEvent.change(tokenInput, { target: { value: 'correct-token' } });

    fireEvent.click(screen.getByRole('button', { name: /Verify & Login/i }));

    await waitFor(() => {
      expect(onLoginSuccess).toHaveBeenCalledWith('admin');
    });
  });

  test('displays error on empty token submission (step 2)', async () => {
    const mockRequestResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockRequestResponse),
      } as Response)
    );

    render(<Login onLoginSuccess={vi.fn()} />);
    
    fireEvent.change(screen.getByPlaceholderText(/e.g. 10001, 10002/i), { target: { value: '10001' } });
    fireEvent.click(screen.getByRole('button', { name: /Request Login Token/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Paste 64-character/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Verify & Login/i }));

    await waitFor(() => {
      expect(screen.getByText(/SHA-256 Token is required./i)).toBeInTheDocument();
    });
  });

  test('displays error on failed token validation login response (step 2)', async () => {
    const mockRequestResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
      if (typeof url === 'string' && url.includes('/api/auth/request-token')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockRequestResponse),
        } as Response);
      }
      return Promise.resolve({
        ok: false,
        json: () => Promise.resolve({ error: 'Incorrect verification code' }),
      } as Response);
    });

    render(<Login onLoginSuccess={vi.fn()} />);
    
    fireEvent.change(screen.getByPlaceholderText(/e.g. 10001, 10002/i), { target: { value: '10001' } });
    fireEvent.click(screen.getByRole('button', { name: /Request Login Token/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Paste 64-character/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText(/Paste 64-character/i), { target: { value: 'wrong-token' } });
    fireEvent.click(screen.getByRole('button', { name: /Verify & Login/i }));

    await waitFor(() => {
      expect(screen.getByText(/Incorrect verification code/i)).toBeInTheDocument();
    });
  });

  test('displays connection error on failed login fetch exception (step 2)', async () => {
    const mockRequestResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) => {
      if (typeof url === 'string' && url.includes('/api/auth/request-token')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockRequestResponse),
        } as Response);
      }
      return Promise.reject(new Error('Connection timed out'));
    });

    render(<Login onLoginSuccess={vi.fn()} />);
    
    fireEvent.change(screen.getByPlaceholderText(/e.g. 10001, 10002/i), { target: { value: '10001' } });
    fireEvent.click(screen.getByRole('button', { name: /Request Login Token/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Paste 64-character/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText(/Paste 64-character/i), { target: { value: 'any-token' } });
    fireEvent.click(screen.getByRole('button', { name: /Verify & Login/i }));

    await waitFor(() => {
      expect(screen.getByText(/Authentication error. Please check your credentials./i)).toBeInTheDocument();
    });
  });

  test('allows backing out from step 2 to step 1', async () => {
    const mockRequestResponse = {
      uid: '10001',
      username: 'admin',
      token: 'mock-sha256-token',
      expiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockRequestResponse),
      } as Response)
    );

    render(<Login onLoginSuccess={vi.fn()} />);
    
    fireEvent.change(screen.getByPlaceholderText(/e.g. 10001, 10002/i), { target: { value: '10001' } });
    fireEvent.click(screen.getByRole('button', { name: /Request Login Token/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Paste 64-character/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Back/i }));

    expect(screen.getByPlaceholderText(/e.g. 10001, 10002/i)).toBeInTheDocument();
  });
});
