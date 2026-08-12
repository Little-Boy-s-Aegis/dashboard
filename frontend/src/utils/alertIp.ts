import type { Alert } from '../types';

type AlertIpSource = Pick<Alert, 'rawLog' | 'description'>;

const isIpExpression = (value: string): boolean => {
  const candidate = value.replace(/^\[|\]$/g, '').split('/')[0];
  const octets = candidate.split('.');
  if (octets.length === 4 && octets.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255)) {
    return true;
  }
  return candidate.includes(':') && /^[0-9a-f:]+$/i.test(candidate);
};

const normalizeIp = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const candidate = value.trim().replace(/^\[|\]$/g, '');
  return isIpExpression(candidate) ? candidate : null;
};

const extractIpFromText = (value?: string): string | null => {
  if (!value) return null;
  const match = value.match(
    /(?:clientIp|client_ip|sourceIp|source_ip|srcIp|src_ip|attacker(?:\s+IP)?|from\s+IP)\s*(?::|=)?\s*["']?(\[[0-9a-f:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:]+)/i,
  );
  return normalizeIp(match?.[1]);
};

export const getAttackerIp = (alert: AlertIpSource): string => {
  if (alert.rawLog) {
    try {
      const parsed = JSON.parse(alert.rawLog);
      const candidates = [
        parsed.verified_case?.entities?.ips?.[0],
        parsed.verifiedCase?.entities?.ips?.[0],
        parsed.clientIp,
        parsed.client_ip,
        parsed.sourceIp,
        parsed.source_ip,
        parsed.srcIp,
        parsed.src_ip,
        parsed.ip,
      ];
      for (const candidate of candidates) {
        const normalized = normalizeIp(candidate);
        if (normalized) return normalized;
      }
    } catch {
      // Some SIEM events contain original plain-text telemetry instead of JSON.
    }
  }

  return extractIpFromText(alert.rawLog) || extractIpFromText(alert.description) || 'N/A';
};
