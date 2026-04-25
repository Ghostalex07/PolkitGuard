import { useState, useEffect, useCallback, useMemo } from 'react';

export enum Severity {
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4,
}

export interface Rule {
  action?: string;
  identity?: string;
  resultAny?: string;
  resultActive?: string;
  resultInactive?: string;
}

export interface Finding {
  severity: Severity;
  ruleId?: string;
  title?: string;
  description?: string;
  message?: string;
  file?: string;
  ruleName?: string;
  rule?: Rule;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  rulesFound: number;
  scanner: string;
  version: string;
}

export interface RiskScore {
  score: number;
  level: string;
  criticality: number;
  likelihood: number;
  impact: number;
}

export interface UsePolkitGuardOptions {
  autoScan?: boolean;
  interval?: number;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  path?: string;
}

export interface UsePolkitGuardReturn {
  result: ScanResult | null;
  risk: RiskScore | null;
  loading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  isHealthy: boolean;
  criticalCount: number;
  highCount: number;
}

export function usePolkitGuard(
  options: UsePolkitGuardOptions = {}
): UsePolkitGuardReturn {
  const {
    autoScan = false,
    interval = 60000,
    severity = 'low',
    path,
  } = options;

  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const risk = useMemo((): RiskScore | null => {
    if (!result) return null;

    const counts = {
      critical: result.findings.filter(f => f.severity === Severity.CRITICAL).length,
      high: result.findings.filter(f => f.severity === Severity.HIGH).length,
      medium: result.findings.filter(f => f.severity === Severity.MEDIUM).length,
      low: result.findings.filter(f => f.severity === Severity.LOW).length,
    };

    const total = Math.max(result.findings.length, 1);
    const score = (counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low * 1) / total;

    let level = 'MINIMAL';
    if (score >= 8) level = 'CRITICAL';
    else if (score >= 6) level = 'HIGH';
    else if (score >= 4) level = 'MEDIUM';
    else if (score >= 2) level = 'LOW';

    return {
      score,
      level,
      criticality: counts.critical / total * 10,
      likelihood: counts.high / total * 10,
      impact: (counts.critical + counts.high) / total * 10,
    };
  }, [result]);

  const refetch = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      params.append('severity', severity);
      if (path) params.append('path', path);

      const response = await fetch(`/polkit/scan?${params.toString()}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity, path }),
      });

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err as Error);
    } finally {
      setLoading(false);
    }
  }, [severity, path]);

  useEffect(() => {
    if (autoScan) {
      refetch();

      if (interval > 0) {
        const timer = setInterval(refetch, interval);
        return () => clearInterval(timer);
      }
    }
  }, [autoScan, interval, refetch]);

  return {
    result,
    risk,
    loading,
    error,
    refetch,
    isHealthy: !result || result.findings.filter(f => f.severity === Severity.CRITICAL).length === 0,
    criticalCount: result?.findings.filter(f => f.severity === Severity.CRITICAL).length || 0,
    highCount: result?.findings.filter(f => f.severity === Severity.HIGH).length || 0,
  };
}

export function PolkitBadge({ severity }: { severity: Severity }) {
  const colors = {
    [Severity.LOW]: 'bg-blue-100 text-blue-800',
    [Severity.MEDIUM]: 'bg-yellow-100 text-yellow-800',
    [Severity.HIGH]: 'bg-orange-100 text-orange-800',
    [Severity.CRITICAL]: 'bg-red-100 text-red-800',
  };

  const labels = {
    [Severity.LOW]: 'LOW',
    [Severity.MEDIUM]: 'MEDIUM',
    [Severity.HIGH]: 'HIGH',
    [Severity.CRITICAL]: 'CRITICAL',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold ${colors[severity]}`}>
      {labels[severity]}
    </span>
  );
}

export function PolkitStatusIndicator({ result }: { result: ScanResult | null }) {
  if (!result) return null;

  const critical = result.findings.filter(f => f.severity === Severity.CRITICAL).length;
  const high = result.findings.filter(f => f.severity === Severity.HIGH).length;

  if (critical > 0) {
    return <span className="text-red-600">⚠️ {critical} Critical</span>;
  }
  if (high > 0) {
    return <span className="text-orange-600">⚠️ {high} High</span>;
  }
  return <span className="text-green-600">✓ Healthy</span>;
}

export default usePolkitGuard;