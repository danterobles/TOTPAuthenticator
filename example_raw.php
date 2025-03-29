<?php

require_once 'src/TOTPAuthenticator.php';

// Example usage
$email = 'drobles@mailinator.com';
$issuer = 'Empresa';

// Create a new authenticator with a random secret
//$auth = new TOTPAuthenticator();
// Or use an existing secret
$auth = new TOTPAuthenticator("BASE32_SECRET");

// Get the secret (store this in your database)
$secret = $auth->getSecret();
echo "🔐 Secret key: $secret\n";

// Generate current TOTP code
$code = $auth->generateCode();
echo "📲 Current OTP: $code\n";

// Verify the code (in a real app, you'd get this from user input)
if ($auth->verifyCode($code)) {
    echo "✅ OTP valid.\n";
} else {
    echo "❌ OTP invalid.\n";
}

// Get a URL for QR code generation
$qrCodeUrl = $auth->getQRCodeUrl($email, $issuer);
echo "🔗 QR code URL: $qrCodeUrl\n";
