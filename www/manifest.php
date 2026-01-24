<?php
declare(strict_types=1);

/**
 * manifest.php
 *
 * Returns a manifest filtered by the authenticated user (Apache BasicAuth).
 *
 * AuthN: Apache (BasicAuth)
 * AuthZ: This script (REMOTE_USER -> ACL -> allowed manifests -> merged entries)
 */

// ====== CONFIG ======
$ACL_PATH = '/etc/codexica/acl.json';
// ====================

// Basic hardening
header_remove('X-Powered-By');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
header('X-Frame-Options: DENY');
header('Cross-Origin-Resource-Policy: same-origin');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cache-Control: private, no-store, max-age=0');

// If and only if you serve over HTTPS:
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

function fail(int $code, string $msg = 'Server error'): void {
    http_response_code($code);
    echo json_encode(['error' => $msg], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function read_json_file(string $path): array {
    if (!is_file($path) || !is_readable($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return [];
    }
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

$user = (string)($_SERVER['REMOTE_USER'] ?? '');
if ($user === '') {
    // If Apache auth is properly configured, this should never happen.
    fail(401, 'Unauthorized');
}

$acl = read_json_file($ACL_PATH);
if ($acl === []) {
    fail(500, 'ACL missing');
}

$manifestMap = $acl['manifests'] ?? null;  // name => absolute path
if (!is_array($manifestMap) || $manifestMap === []) {
    fail(500, 'ACL invalid');
}

$allowedNames = $acl['users'][$user] ?? ($acl['default'] ?? []);
if (!is_array($allowedNames)) {
    $allowedNames = [];
}

// Merge and de-duplicate by UUID
$seen = [];
$merged = [];

$total_files = 0;
$total_dirs = 0;
$total_bytes = 0;

foreach ($allowedNames as $name) {
    if (!is_string($name) || $name === '') {
        continue;
    }
    $mp = $manifestMap[$name] ?? null;
    if (!is_string($mp) || $mp === '') {
        continue;
    }
    $mj = read_json_file($mp);
    if ($mj === []) {
        continue;
    }

    $entries = $mj['entries'] ?? $mj;
    if (!is_array($entries)) {
        continue;
    }

    foreach ($entries as $e) {
        if (!is_array($e)) {
            continue;
        }
        $uuid = (string)($e['uuid'] ?? '');
        if ($uuid === '' || isset($seen[$uuid])) {
            continue;
        }
        $seen[$uuid] = true;
        $merged[] = $e;

        $type = (string)($e['type'] ?? '');
        if ($type === 'directory') {
            $total_dirs++;
        } else {
            $total_files++;
            $sz = $e['size'] ?? 0;
            if (is_int($sz) || is_float($sz)) {
                $total_bytes += (int)$sz;
            }
        }
    }
}

echo json_encode([
    'stats' => [
        'total_files' => $total_files,
        'total_dirs' => $total_dirs,
        'total_bytes' => $total_bytes,
        'user' => $user,
        'buckets' => array_values(array_filter($allowedNames, 'is_string')),
    ],
    'entries' => $merged,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
