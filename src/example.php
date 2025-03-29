<?php
use TOTP\TOTPAuthenticator;

$totp = new TOTPAuthenticator();
$secret = $totp->getSecret();
$code = $totp->generateCode();

echo "Secret key: $secret\n";
echo "TOTP Code: $code\n";
