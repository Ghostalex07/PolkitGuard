<?php

namespace PolkitGuard\Laravel;

use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Cache\TaggedCache;

class PolkitGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/polkitguard.php',
            'polkitguard'
        );

        $this->app->singleton(PolkitGuardScanner::class, function ($app) {
            return new PolkitGuardScanner(
                config('polkitguard.binary_path', 'polkitguard'),
                config('polkitguard.timeout', 60)
            );
        });

        $this->app->alias(PolkitGuardScanner::class, 'polkitguard');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/polkitguard.php' => config_path('polkitguard.php'),
            ], 'polkitguard-config');

            $this->commands([
                \PolkitGuard\Laravel\Commands\ScanCommand::class,
                \PolkitGuard\Laravel\Commands\RiskCommand::class,
            ]);
        }

        $this->app->booted(function () {
            $schedule = $this->app->make(Schedule::class);
            $schedule->command('polkitguard:scan')
                ->dailyAt('02:00')
                ->appendOutputTo(storage_path('logs/polkitguard.log'));
        });
    }
}

class PolkitGuardScanner extends \PolkitGuard\PolkitGuardScanner
{
    public function cachedScan(?string $path = null, string $severity = 'low', int $ttl = 300): ScanResult
    {
        $cacheKey = "polkitguard:scan:" . md5("{$path}:{$severity}");

        return \Illuminate\Support\Facades\Cache::remember($cacheKey, $ttl, function () use ($path, $severity) {
            return $this->scan($path, $severity);
        });
    }

    public function scanWithCache(array $options = [], int $ttl = 300): ScanResult
    {
        $path = $options['path'] ?? null;
        $severity = $options['severity'] ?? 'low';

        return $this->cachedScan($path, $severity, $ttl);
    }
}

namespace PolkitGuard\Laravel\Commands;

use Illuminate\Console\Command;
use PolkitGuard\PolkitGuardScanner;
use PolkitGuard\ScanResult;

class ScanCommand extends Command
{
    protected $signature = 'polkitguard:scan
                            {--path= : Path to scan }
                            {--severity=low : Minimum severity }';

    protected $description = 'Run PolkitGuard security scan';

    public function handle(PolkitGuardScanner $scanner): int
    {
        $path = $this->option('path');
        $severity = $this->option('severity');

        $this->info("Running PolkitGuard scan...");

        try {
            $result = $scanner->scan($path, $severity);

            $this->table(
                ['Severity', 'Rule ID', 'Title', 'File'],
                $this->formatFindings($result->findings)
            );

            $risk = $scanner->calculateRiskScore($result->findings);
            $this->info("Risk Score: {$risk->overall} ({$risk->level})");

            return $result->getCriticalFindings() ? Command::FAILURE : Command::SUCCESS;
        } catch (\Exception $e) {
            $this->error("Scan failed: {$e->getMessage()}");
            return Command::FAILURE;
        }
    }

    private function formatFindings(array $findings): array
    {
        return array_map(fn($f) => [
            $f->severityString(),
            $f->ruleId ?? '-',
            $f->title ?? '-',
            $f->file ?? '-',
        ], $findings);
    }
}