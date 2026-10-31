<?php
namespace app\common\services;

/** Public revocation data only. No device evidence, account data or app signing keys. */
final class AndroidAttestationStatus
{
    public const OFFICIAL_URL = 'https://android.googleapis.com/attestation/status';
    public const MAX_BYTES = 2097152;
    public const MAX_AGE = 86400;

    public static function download(string $url): array
    {
        // Callers construct only a fixed official URL or a pinned GitHub Contents URL.
        if ($url !== self::OFFICIAL_URL && !preg_match(
            '~^https://api\.github\.com/repos/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/contents/status\.json\?ref=main$~D', $url)) {
            throw new \DomainException('source_url_rejected');
        }
        $body = ''; $headers = [];
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'AttestationStatusUpdater/1.0',
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Cache-Control: no-cache'],
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$headers) {
                if (preg_match('~^HTTP/\S+ \d{3}~', $line)) $headers = [];
                elseif (strpos($line, ':') !== false) {
                    [$key, $value] = explode(':', $line, 2);
                    $key = strtolower(trim($key));
                    $headers[$key] = isset($headers[$key]) ? $headers[$key] . ', ' . trim($value) : trim($value);
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($c, $data) use (&$body) {
                if (strlen($body) + strlen($data) > self::MAX_BYTES) return 0;
                $body .= $data; return strlen($data);
            },
        ]);
        $ok = curl_exec($curl); $http = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($ok === false || $http !== 200) throw new \DomainException('source_unreachable');
        return ['body' => $body, 'headers' => $headers, 'received_at' => time()];
    }

    public static function fromOfficial(string $body, array $headers, int $now): array
    {
        self::need(strlen($body) <= self::MAX_BYTES, 'list_too_large');
        $data = json_decode($body, false, 32, JSON_THROW_ON_ERROR);
        self::need($data instanceof \stdClass && isset($data->entries), 'invalid_list');
        self::validateEntries($data->entries);
        $cache = strtolower((string)($headers['cache-control'] ?? ''));
        self::need(!preg_match('/(?:^|,)\s*(no-store|no-cache|private)(?:\s|,|$)/', $cache), 'uncacheable_list');
        self::need(preg_match_all('/(?:^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(?=,|$)/', $cache, $m) === 1, 'missing_cache_lifetime');
        $maxAge = min(self::MAX_AGE, (int)$m[1][0]);
        $sourceDate = strtotime((string)($headers['date'] ?? ''));
        $modified = strtotime((string)($headers['last-modified'] ?? ''));
        $age = (string)($headers['age'] ?? '0');
        self::need($sourceDate !== false && $modified !== false && ctype_digit($age), 'invalid_source_time');
        self::need($sourceDate <= $now + 300 && $modified <= $sourceDate, 'future_source_time');
        // A cached CDN response must not gain another 24 hours when downloaded again.
        $remaining = $maxAge - max((int)$age, max(0, $now - $sourceDate));
        self::need($remaining > 0, 'source_already_stale');
        return [
            'version' => 1, 'source_url' => self::OFFICIAL_URL, 'fetched_at' => $now,
            'expires_at' => $now + $remaining, 'source_date' => $sourceDate,
            'source_last_modified' => $modified, 'entries' => $data->entries,
        ];
    }

    public static function validateEntries($entries): void
    {
        self::need($entries instanceof \stdClass, 'entries_must_be_object');
        foreach ($entries as $serial => $entry) {
            self::need(preg_match('/^[a-f1-9][a-f0-9]{0,127}$/D', (string)$serial) === 1, 'invalid_serial');
            self::need($entry instanceof \stdClass && isset($entry->status)
                && in_array($entry->status, ['REVOKED', 'SUSPENDED'], true), 'invalid_status');
            foreach (array_keys(get_object_vars($entry)) as $key) self::need(in_array($key, ['status','expires','reason','comment'], true), 'unknown_entry_field');
            if (isset($entry->reason)) self::need(in_array($entry->reason, ['UNSPECIFIED','KEY_COMPROMISE','CA_COMPROMISE','SUPERSEDED','SOFTWARE_FLAW'], true), 'invalid_reason');
            if (isset($entry->comment)) self::need(is_string($entry->comment) && strlen($entry->comment) <= 560, 'invalid_comment');
            if (isset($entry->expires)) self::need(is_string($entry->expires) && preg_match('/^\d{4}-\d{2}-\d{2}$/D', $entry->expires), 'invalid_expiry_date');
        }
    }

    public static function validateSnapshot(array $state, int $now): void
    {
        self::need(($state['version'] ?? null) === 1 && ($state['source_url'] ?? '') === self::OFFICIAL_URL, 'snapshot_source');
        foreach (['fetched_at','expires_at','source_date','source_last_modified'] as $key) self::need(isset($state[$key]) && is_int($state[$key]), 'snapshot_time');
        self::need($state['fetched_at'] <= $now + 300 && $state['fetched_at'] > 0, 'future_snapshot');
        self::need($state['expires_at'] > $now && $state['expires_at'] > $state['fetched_at']
            && $state['expires_at'] <= $state['fetched_at'] + self::MAX_AGE
            && $state['expires_at'] <= $state['source_date'] + self::MAX_AGE + 300, 'stale_snapshot');
        self::need($state['source_date'] <= $state['fetched_at'] + 300
            && $state['source_last_modified'] > 0 && $state['source_last_modified'] <= $state['source_date'], 'snapshot_source_time');
        self::validateEntries($state['entries'] ?? null);
    }

    public static function verifyEnvelope(string $json, string $publicKey, int $now): array
    {
        self::need(strlen($json) <= self::MAX_BYTES, 'envelope_too_large');
        $envelope = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        self::need(is_array($envelope) && ($envelope['version'] ?? null) === 1
            && is_string($envelope['payload'] ?? null) && is_string($envelope['signature'] ?? null), 'invalid_envelope');
        $payload = base64_decode($envelope['payload'], true);
        $sig = base64_decode($envelope['signature'], true);
        $key = base64_decode($publicKey, true);
        self::need($payload !== false && $sig !== false && $key !== false
            && strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'invalid_signature_encoding');
        self::need(sodium_crypto_sign_verify_detached($sig, $payload, $key), 'invalid_signature');
        $decoded = json_decode($payload, false, 32, JSON_THROW_ON_ERROR);
        self::need($decoded instanceof \stdClass, 'invalid_payload');
        $state = get_object_vars($decoded);
        self::validateSnapshot($state, $now);
        return $state;
    }

    public static function fromGithub(string $body, string $publicKey, int $now): array
    {
        $wrapper = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        self::need(is_array($wrapper) && ($wrapper['encoding'] ?? '') === 'base64'
            && ($wrapper['type'] ?? '') === 'file' && ($wrapper['path'] ?? '') === 'status.json'
            && is_string($wrapper['content'] ?? null), 'invalid_github_response');
        $json = base64_decode($wrapper['content'], true);
        self::need($json !== false, 'invalid_github_content');
        return self::verifyEnvelope($json, $publicKey, $now);
    }

    public static function save(string $dir, array $state, int $now): void
    {
        self::validateSnapshot($state, $now);
        $lock = fopen($dir.'/.attestation-refresh.lock', 'c');
        self::need($lock !== false && flock($lock, LOCK_EX), 'cache_lock');
        $tmp = null;
        try {
            $path = $dir.'/android-attestation-status.json';
            $old = is_file($path) ? json_decode((string)file_get_contents($path), false) : null;
            if ($old instanceof \stdClass) {
                self::need($state['fetched_at'] >= (int)($old->fetched_at ?? 0), 'snapshot_rollback');
                self::need($state['source_last_modified'] >= (int)($old->source_last_modified ?? 0), 'source_rollback');
                if ($state['fetched_at'] === (int)($old->fetched_at ?? 0)) {
                    self::need(($old->entries ?? null) == $state['entries'], 'snapshot_conflict');
                    return; // The same snapshot must not renew its expiration time.
                }
            }
            $json = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $tmp = tempnam($dir, '.status-');
            self::need($tmp !== false && file_put_contents($tmp, $json) === strlen($json), 'cache_write');
            self::need(chmod($tmp, 0644) && rename($tmp, $path), 'cache_replace');
            $tmp = null;
        } finally {
            if ($tmp !== null && is_file($tmp)) unlink($tmp);
            flock($lock, LOCK_UN); fclose($lock);
        }
    }

    public static function need($ok, string $reason): void
    {
        if (!$ok) throw new \DomainException($reason);
    }
}
