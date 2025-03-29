<?php
namespace TOTP;
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
    private static $base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    /**
     * Constructor
     * 
     * @param string|null $secret Base32 encoded secret (if null, generates a new one)
     * @param int $digits Number of digits in generated code
     * @param int $timeStep Time step in seconds
     */
    public function __construct($secret = null, $digits = 6, $timeStep = 30)
    {
        $this->digits = $digits;
        $this->timeStep = $timeStep;
        
        if ($secret === null) {
            $this->secret = $this->generateSecureSecret();
        } else {
            $this->secret = $secret;
        }
    }
    
    /**
     * Get the current secret
     * 
     * @return string Base32 encoded secret
     */
    public function getSecret()
    {
        return $this->secret;
    }
    
    /**
     * Generate a new secure random secret
     * 
     * @param int $byteLength Length of random bytes before encoding
     * @return string Base32 encoded secret
     */
    public function generateSecureSecret($byteLength = 10)
    {
        $randomBytes = random_bytes($byteLength);
        return $this->encodeBase32($randomBytes);
    }
    
    /**
     * Generate current TOTP code
     * 
     * @return string TOTP code
     */
    public function generateCode()
    {
        $time = floor(time() / $this->timeStep);
        return $this->generateCodeForInterval($time);
    }
    
    /**
     * Generate TOTP code for a specific time interval
     * 
     * @param int $interval Time interval
     * @return string TOTP code
     */
    public function generateCodeForInterval($interval)
    {
        $binaryTime = pack('N*', 0) . pack('N*', $interval);
        $key = $this->base32Decode($this->secret);
        $hash = hash_hmac('sha1', $binaryTime, $key, true);

        $offset = ord($hash[19]) & 0xf;
        $binaryCode = (
            (ord($hash[$offset]) & 0x7f) << 24 |
            (ord($hash[$offset + 1]) & 0xff) << 16 |
            (ord($hash[$offset + 2]) & 0xff) << 8 |
            (ord($hash[$offset + 3]) & 0xff)
        );

        return str_pad($binaryCode % pow(10, $this->digits), $this->digits, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify a user-provided TOTP code
     * 
     * @param string $inputCode Code provided by user
     * @param int $window Window of intervals to check before/after current time
     * @return bool True if code is valid
     */
    public function verifyCode($inputCode, $window = 1)
    {
        $currentInterval = floor(time() / $this->timeStep);
        
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
    public function getQRCodeUrl($accountName, $issuer)
    {
        $issuer = rawurlencode($issuer);
        $accountName = rawurlencode($accountName);
        
        return "otpauth://totp/{$issuer}:{$accountName}?secret={$this->secret}&issuer={$issuer}&digits={$this->digits}&period={$this->timeStep}";
    }
    
    /**
     * Encode binary data to Base32
     * 
     * @param string $binary Binary data to encode
     * @return string Base32 encoded string
     */
    public function encodeBase32($binary)
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
    
    /**
     * Decode Base32 to binary data
     * 
     * @param string $base32 Base32 encoded string
     * @return string Decoded binary data
     */
    public function base32Decode($base32)
    {
        $base32 = strtoupper($base32);
        $bits = '';
        $value = '';

        for ($i = 0; $i < strlen($base32); $i++) {
            $char = $base32[$i];
            $pos = strpos(self::$base32Alphabet, $char);
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
}