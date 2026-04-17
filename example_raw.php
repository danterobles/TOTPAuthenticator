<?php

require_once 'src/TOTPAuthenticator.php';

use TOTP\TOTPAuthenticator;

$email  = 'drobles@mailinator.com';
$issuer = 'Empresa';

// --- 1. Generate a new authenticator with a random secret ---
$auth   = new TOTPAuthenticator();
$secret = $auth->getSecret();
echo "🔐 Secret key: $secret\n";

// --- 2. Generate and verify the current OTP ---
$code = $auth->generateCode();
echo "📲 Current OTP: $code\n";

if ($auth->verifyCode($code)) {
    echo "✅ OTP valid.\n";
} else {
    echo "❌ OTP invalid.\n";
}

// --- 3. QR code URL for authenticator apps ---
$qrCodeUrl = $auth->getQRCodeUrl($email, $issuer);
echo "🔗 QR code URL: $qrCodeUrl\n";

// --- 4. Backup codes for account recovery ---
$backupCodes = $auth->generateBackupCodes(count: 10, length: 10);
echo "\n🔑 Backup codes (show once, store hashed):\n";
foreach ($backupCodes as $i => $backupCode) {
    echo "   " . ($i + 1) . ". $backupCode\n";
}

// Hash before storing in database
$hashedCodes = array_map(fn($c) => password_hash($c, PASSWORD_DEFAULT), $backupCodes);

// --- 5. Custom configuration (8-digit codes, 60-second window) ---
echo "\n⚙️  Custom config (8 digits, 60s step):\n";
$customAuth = new TOTPAuthenticator(secret: null, digits: 8, timeStep: 60);
echo "📲 Custom OTP: " . $customAuth->generateCode() . "\n";

// --- 6. Invalid input handling ---
echo "\n🛡️  Validation examples:\n";

try {
    new TOTPAuthenticator('INVALID!!!');
} catch (\InvalidArgumentException $e) {
    echo "❌ Invalid secret: {$e->getMessage()}\n";
}

try {
    new TOTPAuthenticator(digits: 5);
} catch (\InvalidArgumentException $e) {
    echo "❌ Invalid digits: {$e->getMessage()}\n";
}

try {
    new TOTPAuthenticator(timeStep: 0);
} catch (\InvalidArgumentException $e) {
    echo "❌ Invalid timeStep: {$e->getMessage()}\n";
}
