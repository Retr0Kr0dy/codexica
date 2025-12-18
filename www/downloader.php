<?php
declare(strict_types=1);

/**
 * download.php
 * GET ?q=<uuid>
 *
 * Looks up UUID in manifest.json, resolves a ROOT-relative path, and serves the file.
 * Does NOT leak $DATA_ROOT.
 */

// ====== CONFIG ======
$DATA_ROOT = '/srv/data';                 // private dataset root (NOT exposed)
$MANIFEST_PATH = __DIR__ . '/manifest.json'; // served as /manifest.json, but we read locally
// ====================

// Basic hardening
header_remove('X-Powered-By');

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()');

// Clickjacking protection (modern way is CSP frame-ancestors; keep XFO for legacy)
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
// Optional legacy:
header('X-Frame-Options: DENY');

// Cross-origin leakage control (tune if you intentionally allow cross-origin downloads)
header('Cross-Origin-Resource-Policy: same-origin');
header('Cross-Origin-Opener-Policy: same-origin');

// If and only if you serve over HTTPS:
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

function fail(int $code, string $msg = ''): void {
    http_response_code($code);
    // Keep messages generic to avoid leaking details.
    if ($msg !== '') {
        header('Content-Type: text/plain; charset=utf-8');
        echo $msg;
    }
    exit;
}

$q = $_GET['q'] ?? '';
$q = trim($q);

// Accept UUIDs in canonical form (8-4-4-4-12 hex). If you want to accept other UUID variants, loosen this.
if (!preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $q)) {
    fail(400, "Bad request\n");
}

if (!is_file($MANIFEST_PATH) || !is_readable($MANIFEST_PATH)) {
    fail(500, "Server error\n");
}

$raw = file_get_contents($MANIFEST_PATH);
if ($raw === false) {
    fail(500, "Server error\n");
}

$manifest = json_decode($raw, true);
if (!is_array($manifest)) {
    fail(500, "Server error\n");
}

// Manifest can be either { entries: [...] } or [ ... ]
$entries = $manifest['entries'] ?? $manifest;
if (!is_array($entries)) {
    fail(500, "Server error\n");
}

// Find entry by UUID (O(n)). For big manifests, consider a prebuilt UUID->entry map/cache.
$entry = null;
foreach ($entries as $e) {
    if (is_array($e) && ($e['uuid'] ?? null) === $q) {
        $entry = $e;
        break;
    }
}

if ($entry === null) {
    fail(404, "Not found\n");
}

// Reject directories
$type = (string)($entry['type'] ?? '');
if ($type === 'directory') {
    fail(404, "Not found\n");
}

$relPath = (string)($entry['path'] ?? '');
if ($relPath === '' || str_contains($relPath, "\0")) {
    fail(404, "Not found\n");
}

// Build a full path and validate it stays under DATA_ROOT
$rootReal = realpath($DATA_ROOT);
if ($rootReal === false) {
    fail(500, "Server error\n");
}

// Join + realpath: if file doesn't exist, realpath returns false
$full = $DATA_ROOT . DIRECTORY_SEPARATOR . $relPath;
$fullReal = realpath($full);
if ($fullReal === false) {
    fail(404, "Not found\n");
}

// Ensure resolved path is within root (prevents traversal/symlink tricks)
$rootPrefix = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
if (strpos($fullReal, $rootPrefix) !== 0) {
    fail(404, "Not found\n");
}

if (!is_file($fullReal) || !is_readable($fullReal)) {
    fail(404, "Not found\n");
}

// Serve the file
$filename = basename($relPath);
$mime = $type !== '' ? $type : (mime_content_type($fullReal) ?: 'application/octet-stream');
$size = filesize($fullReal);
if ($size === false) $size = 0;

// Optional: If you want browser display for some types, change "attachment" to "inline"
header('Content-Type: ' . $mime);
header('Content-Length: ' . (string)$size);
header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
header('Cache-Control: private, no-store, max-age=0');

// Stream file (no memory blowups)
if (function_exists('fastcgi_finish_request')) {
    // keep as-is; not required
}

$fp = fopen($fullReal, 'rb');
if ($fp === false) {
    fail(500, "Server error\n");
}

// Clean any output buffers
while (ob_get_level() > 0) {
    ob_end_clean();
}

fpassthru($fp);
fclose($fp);
exit;
