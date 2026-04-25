<?php

namespace PolkitGuard;

require_once __DIR__ . '/Severity.php';
require_once __DIR__ . '/Finding.php';
require_once __DIR__ . '/ScanResult.php';
require_once __DIR__ . '/RiskScore.php';
require_once __DIR__ . '/PolkitGuardScanner.php';

function scan(?string $path = null, string $severity = 'low'): ScanResult
{
    $scanner = new PolkitGuardScanner();
    return $scanner->scan($path, $severity);
}

function riskScore(array $findings): RiskScore
{
    return RiskScore::fromFindings($findings);
}