<?php
declare(strict_types=1);

namespace TOTP;

use InvalidArgumentException;

/**
 * TOTPAuthenticator - A class for generating and validating TOTP codes
 * 
 * Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
 */
class TOTPAuthenticator
{
    /**
     * @var string TOTP secret key in Base32 format
     */
    private $secret;
    
    /**
     * @var int Number of digits in the generated code
     */
    private $digits;
    
    /**
     * @var int Time step in seconds (typically 30)
     */
    private $timeStep;
    
    /**
     * @var string Alphabet used for Base32 encoding/decoding
     */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    /**
     * Constructor
     * 
     * @param string|null $secret Base32 encoded secret (if null, generates a new one)
     * @param int $digits Number of digits in generated code
     * @param int $timeStep Time step in seconds
     */
    public function __construct(?string $secret = null, int $digits = 6, int $timeStep = 30)
    {
        if ($digits < 6 || $digits > 8) {
            throw new InvalidArgumentException("The number of digits must be between 6 and 8.");
        }
        if ($timeStep <= 0) {
            throw new InvalidArgumentException("The time interval must be a positive number.");
        }

        $this->digits = $digits;
        $this->timeStep = $timeStep;
        $this->secret = $secret ?? self::generateSecureSecret();
    }
    
    /**
     * Get the current secret
     * 
     * @return string Base32 encoded secret
     */
    public function getSecret(): string
    {
        return $this->secret;
    }
    
    /**
     * Generate a new secure random secret
     * 
     * @param int $byteLength Length of random bytes before encoding
     * @return string Base32 encoded secret
     */
    public static function generateSecureSecret(int $byteLength = 10): string
    {
        return self::encodeBase32(random_bytes($byteLength));
    }
    
    /**
     * Generate current TOTP code
     * 
     * @return string TOTP code
     */
    public function generateCode(): string
    {
        return $this->generateCodeForInterval((int) floor(time() / $this->timeStep));
    }
    
    /**
     * Generate TOTP code for a specific time interval
     * 
     * @param int $interval Time interval
     * @return string TOTP code
     */
    public function generateCodeForInterval(int $interval): string
    {
        $binaryTime = pack('J', $interval);
        $key = self::base32Decode($this->secret);
        $hash = hash_hmac('sha1', $binaryTime, $key, true);

        $offset = ord($hash[19]) & 0xF;
        $binaryCode = (
            (ord($hash[$offset]) & 0x7F) << 24 |
            (ord($hash[$offset + 1]) & 0xFF) << 16 |
            (ord($hash[$offset + 2]) & 0xFF) << 8 |
            (ord($hash[$offset + 3]) & 0xFF)
        );

        return str_pad((string) ($binaryCode % (10 ** $this->digits)), $this->digits, '0', STR_PAD_LEFT);
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
        if ($window < 0) {
            throw new InvalidArgumentException("The window parameter cannot be negative.");
        }

        $currentInterval = (int) floor(time() / $this->timeStep);

        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals($this->generateCodeForInterval($currentInterval + $i), $inputCode)) {
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
        $encodedIssuer = rawurlencode($issuer);
        $encodedAccount = rawurlencode($accountName);

        return sprintf(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
            $encodedIssuer,
            $encodedAccount,
            $this->secret,
            $encodedIssuer,
            $this->digits,
            $this->timeStep
        );
    }
    
    /**
     * Encode binary data to Base32
     * 
     * @param string $binary Binary data to encode
     * @return string Base32 encoded string
     */
    public static function encodeBase32(string $binary): string
    {
        $base32 = '';
        $buffer = '';

        foreach (str_split($binary) as $byte) {
            $buffer .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        foreach (str_split($buffer, 5) as $chunk) {
            $base32 .= self::BASE32_ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $base32;
    }
    
    /**
     * Decode Base32 to binary data
     * 
     * @param string $base32 Base32 encoded string
     * @return string Decoded binary data
     */
    public static function base32Decode(string $base32): string
    {
        $base32 = strtoupper($base32);
        $bits = '';

        foreach (str_split($base32) as $char) {
            $pos = strpos(self::BASE32_ALPHABET, $char);
            if ($pos !== false) {
                $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
            }
        }

        return pack('C*', ...array_map(fn($byte) => bindec($byte), str_split($bits, 8)));
    }
}