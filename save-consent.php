<?php

/**
 * save-consent.php — Engine Irie
 * ─────────────────────────────────────────────────────────────────────────────
 * Reçoit les données de consentement cookies (POST JSON) et les écrit
 * dans consents.json (NDJSON : une ligne JSON par entrée).
 *
 * SÉCURITÉ IMPLÉMENTÉE :
 *  1. Whitelist des origines autorisées (CORS strict)
 *  2. Méthode POST uniquement
 *  3. Content-Type application/json obligatoire
 *  4. Limite de taille du body (16 Ko max)
 *  5. Rate limiting par IP (30 req / heure, stocké en fichier)
 *  6. Validation et assainissement champ par champ (rien de l'input brut)
 *  7. Reconstruction propre de l'entrée — aucune injection possible
 *  8. Headers de sécurité HTTP (nosniff, no-store, etc.)
 *  9. consents.json et logs protégés par .htaccess automatique
 * 10. Journal des tentatives suspectes dans data/security.log
 * ─────────────────────────────────────────────────────────────────────────────
 */

declare(strict_types=1);

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

// Domaines autorisés — sans slash final
const ALLOWED_ORIGINS = [
    'https://engineirie.com',
    'http://engineirie.com',
    'https://www.engineirie.com',
    'http://www.engineirie.com',
    // 'http://localhost:8002',  // décommenter pour les tests locaux
];

// Fichier de sortie (même dossier, protégé par .htaccess)
define('CONSENT_FILE', __DIR__ . '/consents.json');

// Dossier des fichiers temporaires (rate limit + logs)
define('DATA_DIR',     __DIR__ . '/data');
define('RATE_FILE',    DATA_DIR . '/rate_limit.json');
define('SECURITY_LOG', DATA_DIR . '/security.log');

// Rate limiting
const RATE_LIMIT  = 30;    // requêtes max par IP
const RATE_WINDOW = 3600;  // fenêtre en secondes (1 heure)

// Taille max du body JSON accepté
const MAX_BODY_SIZE = 16384; // 16 Ko

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function sendError(int $code, string $msg): never
{
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function sendSuccess(): never
{
    http_response_code(200);
    echo json_encode(['success' => true]);
    exit;
}

function securityLog(string $event, string $ip, string $detail = ''): void
{
    if (!is_dir(DATA_DIR)) {
        @mkdir(DATA_DIR, 0750, true);
        @file_put_contents(DATA_DIR . '/.htaccess', "Deny from all\n");
    }
    $line = sprintf("[%s] %-25s | IP: %-40s | %s\n", date('c'), $event, $ip, $detail);
    @file_put_contents(SECURITY_LOG, $line, FILE_APPEND | LOCK_EX);
}

function getClientIP(): string
{
    $candidates = [
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        $_SERVER['HTTP_X_REAL_IP']        ?? '',
        $_SERVER['HTTP_X_FORWARDED_FOR']  ?? '',
        $_SERVER['REMOTE_ADDR']           ?? '',
    ];
    foreach ($candidates as $c) {
        $ip = trim(explode(',', $c)[0]);
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return 'inconnue';
}

function sanitizeString(mixed $v, int $maxLen = 255): ?string
{
    if ($v === null || $v === '') return null;
    $s = strip_tags((string)$v);
    $s = htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return mb_substr(trim($s), 0, $maxLen, 'UTF-8');
}

function sanitizeBool(mixed $v): bool
{
    return (bool)$v;
}

function sanitizeInt(mixed $v, int $min = 0, int $max = 999999): ?int
{
    if (!is_numeric($v)) return null;
    return max($min, min($max, (int)$v));
}

function sanitizeList(mixed $v, int $maxItems = 20, int $maxLen = 255): array
{
    if (!is_array($v)) return [];
    return array_values(array_slice(
        array_map(fn($item) => sanitizeString($item, $maxLen), $v),
        0,
        $maxItems
    ));
}

function sanitizePreferences(mixed $v): array
{
    if (!is_array($v)) return ['essential' => true, 'analytics' => false, 'marketing' => false];
    return [
        'essential' => true,
        'analytics' => sanitizeBool($v['analytics'] ?? false),
        'marketing' => sanitizeBool($v['marketing'] ?? false),
    ];
}

// ═══════════════════════════════════════════════════════════════════════════
// HEADERS DE SÉCURITÉ HTTP
// ═══════════════════════════════════════════════════════════════════════════

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, no-cache, must-revalidate');

// ═══════════════════════════════════════════════════════════════════════════
// 1. CORS — VÉRIFICATION DE L'ORIGINE
// ═══════════════════════════════════════════════════════════════════════════

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    if (in_array($origin, ALLOWED_ORIGINS, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Methods: POST');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Max-Age: 86400');
    }
    http_response_code(204);
    exit;
}

if (!in_array($origin, ALLOWED_ORIGINS, true)) {
    $ip = getClientIP();
    securityLog('ORIGIN_REJECTED', $ip, 'Origin: ' . substr($origin, 0, 200));
    sendError(403, 'Origine non autorisée');
}

header('Access-Control-Allow-Origin: ' . $origin);

// ═══════════════════════════════════════════════════════════════════════════
// 2. MÉTHODE HTTP
// ═══════════════════════════════════════════════════════════════════════════

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError(405, 'Méthode non autorisée');
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. CONTENT-TYPE
// ═══════════════════════════════════════════════════════════════════════════

$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (stripos($contentType, 'application/json') === false) {
    $ip = getClientIP();
    securityLog('BAD_CONTENT_TYPE', $ip, substr($contentType, 0, 100));
    sendError(415, 'Content-Type invalide');
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. TAILLE DU BODY
// ═══════════════════════════════════════════════════════════════════════════

$contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength > MAX_BODY_SIZE) {
    $ip = getClientIP();
    securityLog('BODY_TOO_LARGE', $ip, "Declared: {$contentLength}");
    sendError(413, 'Payload trop volumineux');
}

$raw = file_get_contents('php://input', false, null, 0, MAX_BODY_SIZE + 1);
if ($raw === false || empty($raw)) {
    sendError(400, 'Body vide');
}
if (strlen($raw) > MAX_BODY_SIZE) {
    $ip = getClientIP();
    securityLog('BODY_TOO_LARGE', $ip, 'Actual: ' . strlen($raw));
    sendError(413, 'Payload trop volumineux');
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. RATE LIMITING PAR IP
// ═══════════════════════════════════════════════════════════════════════════

$ip = getClientIP();

if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0750, true);
    @file_put_contents(DATA_DIR . '/.htaccess', "Deny from all\n");
}

$rateData = [];
if (file_exists(RATE_FILE)) {
    $rc = @file_get_contents(RATE_FILE);
    if ($rc) $rateData = json_decode($rc, true) ?? [];
}

$now    = time();
$window = $now - RATE_WINDOW;

// Purger les entrées expirées
foreach ($rateData as $storedIp => $timestamps) {
    $rateData[$storedIp] = array_values(array_filter($timestamps, fn($t) => $t > $window));
    if (empty($rateData[$storedIp])) unset($rateData[$storedIp]);
}

$hits = count($rateData[$ip] ?? []);
if ($hits >= RATE_LIMIT) {
    securityLog('RATE_LIMIT_EXCEEDED', $ip, "Hits: {$hits}");
    header('Retry-After: ' . RATE_WINDOW);
    sendError(429, 'Trop de requêtes — réessayez plus tard');
}

$rateData[$ip][] = $now;
@file_put_contents(RATE_FILE, json_encode($rateData), LOCK_EX);

// ═══════════════════════════════════════════════════════════════════════════
// 6. PARSING JSON
// ═══════════════════════════════════════════════════════════════════════════

$input = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE || !is_array($input)) {
    securityLog('INVALID_JSON', $ip, json_last_error_msg());
    sendError(400, 'JSON invalide');
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. RECONSTRUCTION PROPRE DE L'ENTRÉE (aucun champ brut non assaini)
// ═══════════════════════════════════════════════════════════════════════════

$entry = [
    // Données client (assainies)
    'date'            => sanitizeString($input['date']           ?? null, 30),
    'timezone'        => sanitizeString($input['timezone']       ?? null, 60),
    'site'            => sanitizeString($input['site']           ?? null, 100),
    'page'            => sanitizeString($input['page']           ?? null, 255),
    'referrer'        => sanitizeString($input['referrer']       ?? null, 255),
    'language'        => sanitizeString($input['language']       ?? null, 20),
    'languages'       => sanitizeList($input['languages']        ?? [], 10, 20),
    'screen'          => sanitizeString($input['screen']         ?? null, 20),
    'viewport'        => sanitizeString($input['viewport']       ?? null, 20),
    'colorDepth'      => sanitizeInt($input['colorDepth']        ?? null, 1, 64),
    'cookiesEnabled'  => sanitizeBool($input['cookiesEnabled']   ?? false),
    'doNotTrack'      => sanitizeBool($input['doNotTrack']       ?? false),
    'browser'         => sanitizeString($input['browser']        ?? null, 50),
    'os'              => sanitizeString($input['os']             ?? null, 50),
    'device'          => sanitizeString($input['device']         ?? null, 20),
    'sessionDuration' => sanitizeInt($input['sessionDuration']   ?? null, 0, 86400),
    'pagesVisited'    => sanitizeList($input['pagesVisited']     ?? [], 50, 255),
    'preferences'     => sanitizePreferences($input['preferences'] ?? []),

    // Données serveur (fiables — non falsifiables par le client)
    'ip'              => $ip,
    'server_date'     => date('c'),
    'accept_language' => sanitizeString($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null, 100),
    'referer_header'  => sanitizeString($_SERVER['HTTP_REFERER']          ?? null, 255),
];

// ═══════════════════════════════════════════════════════════════════════════
// 8. PROTECTION .htaccess (consents.json + dossier data inaccessibles)
// ═══════════════════════════════════════════════════════════════════════════

$htaccess = __DIR__ . '/.htaccess';
$htBlock  = <<<'HTACCESS'
# =============================================================================
# Protection Engine Irie — auto-généré
# =============================================================================

# ── 1. FORCER HTTPS ───────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
    RewriteEngine On

    # Rediriger HTTP → HTTPS
    RewriteCond %{HTTPS} off
    RewriteCond %{HTTP_HOST} !^localhost [NC]
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

    # Rediriger www → non-www (optionnel, adapter si besoin)
    # RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
    # RewriteRule ^ https://%1%{REQUEST_URI} [R=301,L]
</IfModule>

# ── 2. HEADERS DE SÉCURITÉ HTTP ───────────────────────────────────────────────
<IfModule mod_headers.c>
    # Empêche le navigateur de deviner le type MIME (anti sniffing)
    Header always set X-Content-Type-Options "nosniff"

    # Empêche l'intégration en iframe (anti clickjacking)
    Header always set X-Frame-Options "DENY"

    # Active le filtre XSS des anciens navigateurs
    Header always set X-XSS-Protection "1; mode=block"

    # Politique de référent stricte
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # HSTS : force HTTPS pendant 1 an (activer seulement si HTTPS confirmé)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # Content Security Policy — protège contre les injections XSS
    # Adapte 'self' si tu charges des ressources externes
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://fonts.googleapis.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

    # Désactive la détection de type MIME pour les scripts
    Header always set X-Permitted-Cross-Domain-Policies "none"

    # Supprime la signature du serveur dans les réponses
    Header unset X-Powered-By
    Header always unset X-Powered-By
</IfModule>

# ── 3. CACHER LA SIGNATURE DU SERVEUR ────────────────────────────────────────
ServerSignature Off

# ── 4. BLOQUER L'ACCÈS AUX FICHIERS SENSIBLES ────────────────────────────────
# Bloquer .json, .log, .sql, .bak, .env, .git, fichiers cachés
<FilesMatch "(\.json|\.log|\.sql|\.bak|\.env|\.git|\.htpasswd|\.DS_Store|composer\.lock)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Deny from all
    </IfModule>
</FilesMatch>

# Bloquer tous les .php sauf save-consent.php
<FilesMatch "\.php$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Deny from all
    </IfModule>
</FilesMatch>
<Files "save-consent.php">
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Deny,Allow
        Allow from all
    </IfModule>
</Files>

# ── 5. PROTECTION DES FICHIERS HTML CONTRE L'INJECTION ───────────────────────
<FilesMatch "\.html?$">
    <IfModule mod_headers.c>
        # Empêche le navigateur d'exécuter du contenu injecté
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        # Pas de mise en cache des pages HTML (évite le cache poisoning)
        Header always set Cache-Control "no-store, no-cache, must-revalidate"
        Header always set Pragma "no-cache"
    </IfModule>
</FilesMatch>

# ── 6. DÉSACTIVER LE LISTAGE DES RÉPERTOIRES ─────────────────────────────────
Options -Indexes -ExecCGI

# ── 7. BLOQUER LES USER-AGENTS MALVEILLANTS CONNUS ───────────────────────────
<IfModule mod_rewrite.c>
    RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|nmap|masscan|zgrab|python-requests|curl\/[0-2]\.|libwww-perl|scrapy|wget) [NC]
    RewriteRule .* - [F,L]
</IfModule>

# ── 8. BLOQUER LES TENTATIVES D'INJECTION DANS L'URL ─────────────────────────
<IfModule mod_rewrite.c>
    # Bloquer les tentatives de traversée de répertoire
    RewriteCond %{REQUEST_URI} (\.\./|\.\.\\) [NC]
    RewriteRule .* - [F,L]

    # Bloquer les injections SQL communes dans l'URL
    RewriteCond %{QUERY_STRING} (union.*select|insert.*into|drop.*table|script.*>|<.*script) [NC]
    RewriteRule .* - [F,L]

    # Bloquer les tentatives XSS dans l'URL
    RewriteCond %{QUERY_STRING} (<script|javascript:|vbscript:|onload=|onerror=) [NC]
    RewriteRule .* - [F,L]
</IfModule>

# ── 9. LIMITER LES MÉTHODES HTTP AUTORISÉES ──────────────────────────────────
<LimitExcept GET POST OPTIONS>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Deny from all
    </IfModule>
</LimitExcept>

# ── 10. TAILLE MAX DES REQUÊTES (anti flood) ─────────────────────────────────
LimitRequestBody 102400

HTACCESS;

if (!file_exists($htaccess)) {
    @file_put_contents($htaccess, $htBlock);
} elseif (strpos((string)@file_get_contents($htaccess), 'Protection Engine Irie') === false) {
    @file_put_contents($htaccess, $htBlock, FILE_APPEND | LOCK_EX);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. ÉCRITURE DANS CONSENTS.JSON
// ═══════════════════════════════════════════════════════════════════════════

if (!file_exists(CONSENT_FILE)) {
    @file_put_contents(CONSENT_FILE, '');
    @chmod(CONSENT_FILE, 0640);
}

if (!is_writable(CONSENT_FILE)) {
    securityLog('FILE_NOT_WRITABLE', $ip, CONSENT_FILE);
    sendError(500, 'Erreur serveur');
}

$line   = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
$result = file_put_contents(CONSENT_FILE, $line, FILE_APPEND | LOCK_EX);

if ($result === false) {
    securityLog('WRITE_FAILED', $ip, CONSENT_FILE);
    sendError(500, 'Erreur serveur');
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. SUCCÈS
// ═══════════════════════════════════════════════════════════════════════════

sendSuccess();