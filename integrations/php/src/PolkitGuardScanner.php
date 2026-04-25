<?php

namespace PolkitGuard;

use RuntimeException;

class PolkitGuardScanner
{
    private string $binaryPath;
    private int $timeout;

    public function __construct(string $binaryPath = 'polkitguard', int $timeout = 60)
    {
        $this->binaryPath = $this->findBinary($binaryPath);
        $this->timeout = $timeout;
    }

    public function scan(?string $path = null, string $severity = 'low', string $format = 'json'): ScanResult
    {
        $args = [$this->binaryPath, '--format', $format, '--severity', $severity];

        if ($path !== null) {
            $args[] = '--path';
            $args[] = $path;
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($args, $descriptors, $pipes);

        if (!is_resource($process)) {
            throw new RuntimeException('Failed to start polkitguard process');
        }

        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($exitCode !== 0) {
            throw new RuntimeException("Scan failed: {$stderr}");
        }

        if ($format === 'json') {
            $data = json_decode($stdout, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException('Failed to parse JSON output');
            }
            return ScanResult::fromArray($data);
        }

        $result = new ScanResult();
        foreach (explode("\n", $stdout) as $line) {
            if (preg_match('/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/', $line, $matches)) {
                $result->findings[] = Finding::fromArray([
                    'severity' => Severity::fromString($matches[1]),
                ]);
            }
        }

        return $result;
    }

    public function calculateRiskScore(array $findings): RiskScore
    {
        return RiskScore::fromFindings($findings);
    }

    public function getVersion(): string
    {
        return '1.18.0';
    }

    private function findBinary(string $name): string
    {
        $paths = [
            "/usr/local/bin/{$name}",
            "/usr/bin/{$name}",
        ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return $name;
    }
}