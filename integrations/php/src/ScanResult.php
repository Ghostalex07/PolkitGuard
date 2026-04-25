<?php

namespace PolkitGuard;

class ScanResult
{
    /** @var Finding[] */
    public array $findings = [];
    public string $scanner = 'PolkitGuard';
    public array $stats = [];
    public string $version = '1.18.0';

    public static function fromArray(array $data): self
    {
        $result = new self();
        $result->findings = array_map(
            fn($f) => Finding::fromArray($f),
            $data['findings'] ?? []
        );
        $result->scanner = $data['scanner'] ?? 'PolkitGuard';
        $result->stats = $data['stats'] ?? [];
        $result->version = $data['version'] ?? '1.18.0';
        return $result;
    }

    public function getFilesScanned(): int
    {
        return $this->stats['files_scanned'] ?? 0;
    }

    public function getRulesFound(): int
    {
        return $this->stats['rules_found'] ?? 0;
    }

    public function getTotalFindings(): int
    {
        return count($this->findings);
    }

    /**
     * @return Finding[]
     */
    public function getCriticalFindings(): array
    {
        return array_filter($this->findings, fn($f) => $f->isCritical());
    }

    /**
     * @return Finding[]
     */
    public function getHighFindings(): array
    {
        return array_filter($this->findings, fn($f) => $f->isHigh());
    }

    public function isEmpty(): bool
    {
        return empty($this->findings);
    }
}