<?php

namespace PolkitGuard;

class Finding
{
    public int $severity;
    public ?string $file = null;
    public ?string $ruleName = null;
    public ?string $ruleId = null;
    public ?string $title = null;
    public ?string $description = null;
    public ?string $message = null;
    public ?string $impact = null;
    public ?string $recommendation = null;
    public int $score = 0;
    public ?string $cve = null;
    public ?string $action = null;
    public ?string $identity = null;

    public static function fromArray(array $data): self
    {
        $finding = new self();
        $finding->severity = $data['Severity'] ?? $data['severity'] ?? Severity::LOW;
        $finding->file = $data['File'] ?? $data['file'] ?? null;
        $finding->ruleName = $data['RuleName'] ?? $data['ruleName'] ?? null;
        $finding->ruleId = $data['RuleID'] ?? $data['ruleId'] ?? null;
        $finding->title = $data['Title'] ?? $data['title'] ?? null;
        $finding->description = $data['Description'] ?? $data['description'] ?? null;
        $finding->message = $data['Message'] ?? $data['message'] ?? null;
        $finding->impact = $data['Impact'] ?? $data['impact'] ?? null;
        $finding->recommendation = $data['Recommendation'] ?? $data['recommendation'] ?? null;
        $finding->score = $data['Score'] ?? $data['score'] ?? 0;
        $finding->cve = $data['CVE'] ?? $data['cve'] ?? null;

        if (isset($data['Rule']) && is_array($data['Rule'])) {
            $finding->action = $data['Rule']['Action'] ?? null;
            $finding->identity = $data['Rule']['Identity'] ?? null;
        }

        return $finding;
    }

    public function severityString(): string
    {
        return Severity::toString($this->severity);
    }

    public function isCritical(): bool
    {
        return $this->severity === Severity::CRITICAL;
    }

    public function isHigh(): bool
    {
        return $this->severity === Severity::HIGH;
    }
}