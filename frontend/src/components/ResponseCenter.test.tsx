import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ResponseCenter from './ResponseCenter';

describe('ResponseCenter Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const mockProps = {
    agents: [
      {
        id: 'agent-01',
        name: 'Web-Prod-01',
        ip: '192.168.10.11',
        os: 'Linux',
        status: 'active' as const,
        lastSeen: new Date().toISOString(),
        cpuUsage: 12,
        ramUsage: 45,
        diskUsage: 30,
        networkIn: 100,
        networkOut: 120,
        threatScore: 50
      },
      {
        id: 'agent-02',
        name: 'Web-Prod-02',
        ip: '192.168.10.12',
        os: 'Linux',
        status: 'disconnected' as const,
        lastSeen: new Date().toISOString(),
        cpuUsage: 0,
        ramUsage: 0,
        diskUsage: 0,
        networkIn: 0,
        networkOut: 0,
        threatScore: 0
      }
    ],
    alerts: [
      {
        id: 'al-01',
        ruleId: 'rule-01',
        severity: 'high' as const,
        title: 'High anomaly detected',
        description: 'info',
        agentId: 'agent-01',
        agentName: 'Web-Prod-01',
        mitreTechnique: 'T1059',
        mitreTactics: ['Execution'],
        category: 'Malware',
        timestamp: new Date().toISOString(),
        rawLog: 'raw',
        status: 'open' as const
      }
    ],
    actions: [
      { id: 'act-01', timestamp: new Date().toISOString(), actor: 'AI Agent', actionType: 'Isolate Host', target: '192.168.10.11', status: 'success' as const, message: 'Host isolated successfully.' },
      { id: 'act-02', timestamp: new Date().toISOString(), actor: 'admin', actionType: 'Block IP', target: '10.0.0.5', status: 'failed' as const, message: 'Block IP command failed.' }
    ],
    timeRange: '24h',
    setTimeRange: vi.fn(),
    onRefresh: vi.fn(),
    currentUser: 'admin'
  };

  test('renders response center operator details and title', async () => {
    render(<ResponseCenter {...mockProps} />);

    expect(screen.getByText(/RESPONSE CENTER/i)).toBeInTheDocument();
    expect(screen.getByText(/SOC \(admin\)/i)).toBeInTheDocument();
    
    // Verifies rendering action logs for AI Agent and admin
    expect(screen.getByText(/AI Agent/i)).toBeInTheDocument();
    expect(screen.getByText(/Host isolated successfully./i)).toBeInTheDocument();
    expect(screen.getByText(/Block IP command failed./i)).toBeInTheDocument();
  });

  test('enforces client-side ip address input filters', async () => {
    render(<ResponseCenter {...mockProps} />);

    const selectActions = screen.getAllByRole('combobox') as HTMLSelectElement[];
    const selectAction = selectActions.find(el => el.value === 'Isolate Host' || el.value === 'Block IP')!;
    if (selectAction.value === 'Isolate Host') {
      fireEvent.change(selectAction, { target: { value: 'Block IP' } });
    }

    const inputTarget = screen.getByPlaceholderText(/e.g. 198.51.100.222/i) as HTMLInputElement;

    fireEvent.change(inputTarget, { target: { value: '192.abc.1.1' } });
    expect(inputTarget.value).toBe('192..1.1');

    fireEvent.change(inputTarget, { target: { value: '192.168.1.123456789' } });
    expect(inputTarget.value).toBe('192.168.1.12345');
  });

  test('enforces client-side message sanitizer character filters', async () => {
    render(<ResponseCenter {...mockProps} />);

    const messageInput = screen.getByPlaceholderText(/Optional comment\/reason.../i) as HTMLInputElement;

    fireEvent.change(messageInput, { target: { value: '<script>alert(1)</script>' } });
    expect(messageInput.value).toBe('scriptalert(1)/script');

    fireEvent.change(messageInput, { target: { value: 'a'.repeat(120) } });
    expect(messageInput.value).toBe('a'.repeat(100));
  });

  test('remediation form submission validation - missing target', async () => {
    render(<ResponseCenter {...mockProps} />);

    const selectActions = screen.getAllByRole('combobox') as HTMLSelectElement[];
    const selectAction = selectActions.find(el => el.value === 'Isolate Host' || el.value === 'Block IP')!;
    if (selectAction.value === 'Isolate Host') {
      fireEvent.change(selectAction, { target: { value: 'Block IP' } });
    }

    const submitBtn = screen.getByRole('button', { name: /Deploy Mitigation/i });
    fireEvent.click(submitBtn);

    expect(screen.getByText(/Target value is required./i)).toBeInTheDocument();
  });

  test('remediation form submission success flow', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      } as Response)
    );

    render(<ResponseCenter {...mockProps} />);

    // Change action type to Block IP
    const selectActions = screen.getAllByRole('combobox') as HTMLSelectElement[];
    const selectAction = selectActions.find(el => el.value === 'Isolate Host' || el.value === 'Block IP')!;
    if (selectAction.value === 'Isolate Host') {
      fireEvent.change(selectAction, { target: { value: 'Block IP' } });
    }

    const inputTarget = screen.getByPlaceholderText(/e.g. 198.51.100.222/i) as HTMLInputElement;
    fireEvent.change(inputTarget, { target: { value: '192.168.1.5' } });

    const submitBtn = screen.getByRole('button', { name: /Deploy Mitigation/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/actions', expect.any(Object));
      expect(screen.getByText(/Triggered Block IP on 192.168.1.5 successfully/i)).toBeInTheDocument();
      expect(mockProps.onRefresh).toHaveBeenCalled();
    });
  });

  test('remediation form submission server error flow', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve({
        ok: false,
        json: () => Promise.resolve({ error: 'Database constraint failed' }),
      } as Response)
    );

    render(<ResponseCenter {...mockProps} />);

    // Change action type to Block IP
    const selectActions = screen.getAllByRole('combobox') as HTMLSelectElement[];
    const selectAction = selectActions.find(el => el.value === 'Isolate Host' || el.value === 'Block IP')!;
    if (selectAction.value === 'Isolate Host') {
      fireEvent.change(selectAction, { target: { value: 'Block IP' } });
    }

    const inputTarget = screen.getByPlaceholderText(/e.g. 198.51.100.222/i) as HTMLInputElement;
    fireEvent.change(inputTarget, { target: { value: '192.168.1.5' } });

    const submitBtn = screen.getByRole('button', { name: /Deploy Mitigation/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Database constraint failed/i)).toBeInTheDocument();
    });
  });

  test('remediation form submission network exception flow', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.reject(new Error('Connection timed out'))
    );

    render(<ResponseCenter {...mockProps} />);

    // Change action type to Block IP
    const selectActions = screen.getAllByRole('combobox') as HTMLSelectElement[];
    const selectAction = selectActions.find(el => el.value === 'Isolate Host' || el.value === 'Block IP')!;
    if (selectAction.value === 'Isolate Host') {
      fireEvent.change(selectAction, { target: { value: 'Block IP' } });
    }

    const inputTarget = screen.getByPlaceholderText(/e.g. 198.51.100.222/i) as HTMLInputElement;
    fireEvent.change(inputTarget, { target: { value: '192.168.1.5' } });

    const submitBtn = screen.getByRole('button', { name: /Deploy Mitigation/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Network error triggered./i)).toBeInTheDocument();
    });
  });
});
