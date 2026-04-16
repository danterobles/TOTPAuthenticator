<?php
namespace TOTP;

/**
 * TOTPAuthenticator - A class for generating and validating TOTP codes
 *
 * Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
 */
class TOTPAuthenticator
{
    private string $secret;
    private int $digits;
    private int $timeStep;

    private static string $base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * @param string|null $secret Base32 encoded secret (if null, generates a new one)
     * @param int $digits Number of digits in generated code (between 6 and 8)
     * @param int $timeStep Time step in seconds (must be positive)
     * @throws \InvalidArgumentException
     */
    public function __construct(?string $secret = null, int $digits = 6, int $timeStep = 30)
    {
        if ($digits < 6 || $digits > 8) {
            throw new \InvalidArgumentException('Digits must be between 6 and 8.');
        }

        if ($timeStep <= 0) {
            throw new \InvalidArgumentException('Time step must be a positive integer.');
        }

        $this->digits   = $digits;
        $this->timeStep = $timeStep;

        if ($secret === null) {
            $this->secret = $this->generateSecureSecret();
        } else {
            $this->validateSecret($secret);
            $this->secret = strtoupper($secret);
        }
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function generateSecureSecret(int $byteLength = 20): string
    {
        if ($byteLength < 16) {
            throw new \InvalidArgumentException('Secret must be at least 16 bytes (128 bits) per RFC recommendation.');
        }

        $randomBytes = random_bytes($byteLength);
        return $this->encodeBase32($randomBytes);
    }

    public function generateCode(): string
    {
        $time = (int) floor(time() / $this->timeStep);
        return $this->generateCodeForInterval($time);
    }

    /**
     * Verify a user-provided TOTP code
     *
     * @param string $inputCode Code provided by user
     * @param int $window Window of intervals to check before/after current time
     * @return bool True if code is valid
     */
    public function verifyCode(string $inputCode, int $window = 1): bool
    {
        if (!ctype_digit($inputCode) || strlen($inputCode) !== $this->digits) {
            return false;
        }

        $currentInterval = (int) floor(time() / $this->timeStep);

        for ($i = -$window; $i <= $window; $i++) {
            $code = $this->generateCodeForInterval($currentInterval + $i);
            if (hash_equals($code, $inputCode)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a URL for use with QR codes (compatible with Google Authenticator)
     *
     * @param string $accountName Account name or email
     * @param string $issuer Name of the service/company providing authentication
     * @return string otpauth:// URL for QR code
     */
    public function getQRCodeUrl(string $accountName, string $issuer): string
    {
        $encodedIssuer  = rawurlencode($issuer);
        $encodedAccount = rawurlencode($accountName);

        return "otpauth://totp/{$encodedIssuer}:{$encodedAccount}?secret={$this->secret}&issuer={$encodedIssuer}&digits={$this->digits}&period={$this->timeStep}";
    }

    /**
     * Generate backup codes for account recovery.
     * Store hashed versions in your database; show plain codes only once to the user.
     *
     * @param int $count Number of codes to generate
     * @param int $length Character length of each code
     * @return string[] Plain-text backup codes
     */
    public function generateBackupCodes(int $count = 10, int $length = 10): array
    {
        if ($count < 1) {
            throw new \InvalidArgumentException('Count must be at least 1.');
        }

        if ($length < 8) {
            throw new \InvalidArgumentException('Backup code length must be at least 8 characters.');
        }

        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = substr(bin2hex(random_bytes((int) ceil($length / 2))), 0, $length);
        }

        return $codes;
    }

    public function encodeBase32(string $binary): string
    {
        $base32 = '';
        $buffer = '';

        for ($i = 0; $i < strlen($binary); $i++) {
            $buffer .= str_pad(decbin(ord($binary[$i])), 8, '0', STR_PAD_LEFT);
        }

        for ($i = 0; $i < strlen($buffer); $i += 5) {
            $chunk = substr($buffer, $i, 5);
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $base32 .= self::$base32Alphabet[bindec($chunk)];
        }

        return $base32;
    }

    public function base32Decode(string $base32): string
    {
        $base32 = strtoupper($base32);
        $bits   = '';
        $value  = '';

        for ($i = 0; $i < strlen($base32); $i++) {
            $char = $base32[$i];
            $pos  = strpos(self::$base32Alphabet, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
            $value .= chr(bindec(substr($bits, $i, 8)));
        }

        return $value;
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function validateSecret(string $secret): void
    {
        if (strlen($secret) === 0) {
            throw new \InvalidArgumentException('Secret cannot be empty.');
        }

        // Base32 alphabet: A-Z and 2-7, optional padding with =
        if (!preg_match('/^[A-Z2-7]+=*$/i', $secret)) {
            throw new \InvalidArgumentException('Secret contains invalid Base32 characters.');
        }

        // Decoded bytes: minimum 16 bytes (128 bits) per RFC recommendation
        $decoded = $this->base32Decode($secret);
        if (strlen($decoded) < 16) {
            throw new \InvalidArgumentException('Secret is too short. Minimum 128 bits (16 decoded bytes) required.');
        }
    }

    private function generateCodeForInterval(int $interval): string
    {
        $binaryTime = pack('N*', 0) . pack('N*', $interval);
        $key        = $this->base32Decode($this->secret);
        $hash       = hash_hmac('sha1', $binaryTime, $key, true);

        $offset     = ord($hash[19]) & 0xf;
        $binaryCode = (
            (ord($hash[$offset])     & 0x7f) << 24 |
            (ord($hash[$offset + 1]) & 0xff) << 16 |
            (ord($hash[$offset + 2]) & 0xff) << 8  |
            (ord($hash[$offset + 3]) & 0xff)
        );

        return str_pad($binaryCode % (int) pow(10, $this->digits), $this->digits, '0', STR_PAD_LEFT);
    }
}
