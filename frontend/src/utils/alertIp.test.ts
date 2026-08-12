import { describe, expect, it } from 'vitest';
import { getAttackerIp } from './alertIp';

describe('getAttackerIp', () => {
  it('reads the attacker IP from structured bank alert JSON', () => {
    expect(getAttackerIp({
      rawLog: '{"clientIp":"172.23.0.1","attackType":"SQL_INJECTION"}',
      description: 'Blocked SQL injection attempt.',
    })).toBe('172.23.0.1');
  });

  it('reads the attacker IP from an L2 verified case', () => {
    expect(getAttackerIp({
      rawLog: '{"verified_case":{"entities":{"ips":["42.114.204.232"]}}}',
      description: '',
    })).toBe('42.114.204.232');
  });

  it('falls back to the alert description for plain-text SIEM telemetry', () => {
    expect(getAttackerIp({
      rawLog: '/api/logs?limit=25&unexpected-text',
      description: 'An adversarial pattern was detected on service app from IP 127.0.0.1. Category: SECURITY_EVENT',
    })).toBe('127.0.0.1');
  });

  it('does not invent an attacker IP when no labelled IP exists', () => {
    expect(getAttackerIp({
      rawLog: '2026-08-12 startup completed on port 8080',
      description: 'Operational event without a source address.',
    })).toBe('N/A');
  });
});
