<?php

namespace PolkitGuard;

class RiskScore
{
    public float $overall;
    public string $level;
    public float $criticality;
    public float $likelihood;
    public float $impact;
    public array $recommendations = [];

    public static function fromFindings(array $findings): self
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($findings as $f) {
            switch ($f->severity) {
                case Severity::CRITICAL:
                    $counts['critical']++;
                    break;
                case Severity::HIGH:
                    $counts['high']++;
                    break;
                case Severity::MEDIUM:
                    $counts['medium']++;
                    break;
                default:
                    $counts['low']++;
            }
        }

        $total = max(count($findings), 1);
        $score = new self();

        $score->overall = ($counts['critical'] * 10 + $counts['high'] * 7 + $counts['medium'] * 4 + $counts['low'] * 1) / $total;
        $score->criticality = $counts['critical'] / $total * 10;
        $score->likelihood = $counts['high'] / $total * 10;
        $score->impact = ($counts['critical'] + $counts['high']) / $total * 10;

        $score->level = match (true) {
            $score->overall >= 8 => 'CRITICAL',
            $score->overall >= 6 => 'HIGH',
            $score->overall >= 4 => 'MEDIUM',
            $score->overall >= 2 => 'LOW',
            default => 'MINIMAL',
        };

        if ($counts['critical'] > 0) {
            $score->recommendations[] = 'URGENT: Critical issues found. Immediate action required.';
        }
        if ($counts['high'] > 0) {
            $score->recommendations[] = 'High priority: Review and remediate within 24 hours.';
        }
        if ($counts['medium'] > 0) {
            $score->recommendations[] = 'Medium priority: Schedule remediation within 1 week.';
        }

        return $score;
    }

    public function __toString(): string
    {
        return sprintf("Risk Score: %.1f (%s)", $this->overall, $this->level);
    }
}