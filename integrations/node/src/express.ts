import express, { Request, Response, NextFunction, Router } from 'express';
import { PolkitGuard, ScanResult, ScanOptions, RiskScore } from '../src/index';

export interface PolkitGuardMiddlewareOptions {
  severity?: 'low' | 'medium' | 'high' | 'critical';
  cacheEnabled?: boolean;
  cacheTimeout?: number;
}

export interface PolkitGuardRouteOptions {
  path?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

const scanCache = new Map<string, { result: ScanResult; timestamp: number }>();

export class PolkitGuardExpress {
  private guard: PolkitGuard;
  private cacheTimeout: number;

  constructor(options: PolkitGuardMiddlewareOptions = {}) {
    this.guard = new PolkitGuard({
      binaryPath: process.env.POLKITGUARD_BINARY,
    });
    this.cacheTimeout = options.cacheTimeout || 300000;
  }

  middleware(options: PolkitGuardMiddlewareOptions = {}) {
    return (req: Request, res: Response, next: NextFunction) => {
      const cacheKey = `${req.method}:${req.path}:${options.severity || 'low'}`;

      if (options.cacheEnabled && scanCache.has(cacheKey)) {
        const cached = scanCache.get(cacheKey)!;
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          res.locals.polkitResult = cached.result;
          return next();
        }
      }

      const scanOptions: ScanOptions = {
        severity: options.severity || 'low',
        path: req.body?.path || req.query?.path as string,
      };

      this.guard.scan(scanOptions)
        .then(result => {
          if (options.cacheEnabled) {
            scanCache.set(cacheKey, { result, timestamp: Date.now() });
          }
          res.locals.polkitResult = result;
          next();
        })
        .catch(next);
    };
  }

  router(): Router {
    const router = Router();

    router.post('/scan', async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { path, severity = 'low', format = 'json' } = req.body;
        const result = await this.guard.scan({ path, severity, format });

        if (format === 'json') {
          res.json(result);
        } else {
          res.send(result);
        }
      } catch (error) {
        next(error);
      }
    });

    router.post('/risk', async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { path, severity = 'low' } = req.body;
        const result = await this.guard.scan({ path, severity });
        const risk = this.guard.calculateRiskScore(result.findings);

        res.json({
          ...risk,
          findings: result.findings,
          stats: result.stats,
        });
      } catch (error) {
        next(error);
      }
    });

    router.get('/health', async (req: Request, res: Response) => {
      try {
        const result = await this.guard.scan({ severity: 'critical' });
        const status = result.findings.length === 0 ? 'healthy' : 'unhealthy';

        res.json({
          status,
          critical: result.findings.filter(f => f.severity === 4).length,
          high: result.findings.filter(f => f.severity === 3).length,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        res.status(500).json({ status: 'error', message: (error as Error).message });
      }
    });

    router.get('/version', (req: Request, res: Response) => {
      res.json({ version: this.guard.version });
    });

    return router;
  }

  requirePolkit(options: PolkitGuardRouteOptions = {}) {
    return (req: Request, res: Response, next: NextFunction) => {
      this.guard.scan({ severity: options.severity || 'low', path: options.path })
        .then(result => {
          if (result.findings.some(f => f.severity === 4)) {
            return res.status(403).json({
              error: 'Critical findings detected',
              findings: result.findings.filter(f => f.severity === 4),
            });
          }
          res.locals.polkitResult = result;
          next();
        })
        .catch(next);
    };
  }
}

export function createPolkitRouter(options: PolkitGuardMiddlewareOptions = {}): Router {
  const polkit = new PolkitGuardExpress(options);
  return polkit.router();
}

export function polkitScan(req: Request, res: Response, next: NextFunction) {
  const polkit = new PolkitGuardExpress();
  polkit.guard.scan({
    path: req.body?.path || req.query?.path as string,
    severity: (req.query?.severity as any) || 'low',
  })
    .then(result => {
      res.json(result);
    })
    .catch(next);
}

export function polkitRisk(req: Request, res: Response, next: NextFunction) {
  const polkit = new PolkitGuardExpress();
  polkit.guard.scan({
    severity: (req.query?.severity as any) || 'low',
  })
    .then(result => {
      res.json(polkit.guard.calculateRiskScore(result.findings));
    })
    .catch(next);
}