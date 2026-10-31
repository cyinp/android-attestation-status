<?php
// This repository publishes Google's public list only. Never add application/user data.
require __DIR__.'/lib/AndroidAttestationStatus.php';
use app\common\services\AndroidAttestationStatus as S;
try {
    $secret = base64_decode((string)getenv('ATTESTATION_SIGNING_KEY'), true);
    S::need($secret !== false && strlen($secret) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'missing_signing_key');
    $r=S::download(S::OFFICIAL_URL);
    $state=S::fromOfficial($r['body'],$r['headers'],$r['received_at']);
    // Do not publish a snapshot about to expire before the consumer's next hourly poll.
    S::need($state['expires_at']-time()>=7200,'source_lifetime_too_short');
    if (is_file(__DIR__.'/status.json')) {
        $prior=json_decode((string)file_get_contents(__DIR__.'/status.json'),true);
        $bytes=base64_decode((string)($prior['payload']??''),true);
        $sig=base64_decode((string)($prior['signature']??''),true);
        S::need($bytes!==false && $sig!==false && strlen($sig)===SODIUM_CRYPTO_SIGN_BYTES
            && sodium_crypto_sign_verify_detached($sig,$bytes,sodium_crypto_sign_publickey_from_secretkey($secret)), 'previous_signature_invalid');
        $old=json_decode($bytes,true,32,JSON_THROW_ON_ERROR);
        S::need($state['fetched_at']>(int)$old['fetched_at']
            && $state['source_last_modified']>=(int)$old['source_last_modified'],'source_rollback');
    }
    $payload=json_encode($state,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    $signature=sodium_crypto_sign_detached($payload,$secret);
    sodium_memzero($secret);
    $json=json_encode(['version'=>1,'payload'=>base64_encode($payload),'signature'=>base64_encode($signature)],JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES).PHP_EOL;
    S::need(file_put_contents(__DIR__.'/status.json',$json)===strlen($json),'publish_write_failed');
    echo json_encode(['ok'=>true,'entries'=>count(get_object_vars($state['entries'])),'expires_at'=>$state['expires_at']]).PHP_EOL;
} catch (Throwable $e) {
    fwrite(STDERR,"Public status refresh failed; previous signed snapshot retained.\n");exit(1);
}
