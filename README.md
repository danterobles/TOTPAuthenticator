# TOTP Authenticator for PHP

## Overview

`TOTPAuthenticator` is a PHP class that implements Time-based One-Time Password (TOTP) authentication according to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). It provides a secure way to implement two-factor authentication (2FA) in your PHP applications, compatible with popular authenticator apps like Google Authenticator, Microsoft Authenticator, and Authy.

## Features

- Generate secure random secrets for TOTP authentication
- Create and validate time-based one-time passwords
- Generate QR code URLs for easy setup with authenticator apps
- Customizable code length and time step
- Built-in Base32 encoding/decoding
- Compatible with all standard TOTP authenticator applications

## Installation

### Raw PHP

1. Simply include the `TOTPAuthenticator.php` file in your project:

```php
require_once 'path/to/TOTPAuthenticator.php';
```

### Laravel

1. Create a new directory in your Laravel project:
```bash
mkdir -p app/Services/Auth
```

2. Copy the `TOTPAuthenticator.php` file to this directory and update the namespace:

```php
<?php

namespace App\Services\Auth;

/**
 * TOTPAuthenticator - A class for generating and validating TOTP codes
 * 
 * Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
 */
class TOTPAuthenticator
{
    // Class content remains the same
}
```

3. Optionally, register it as a service in the service container by adding to your `AppServiceProvider`:

```php
use App\Services\Auth\TOTPAuthenticator;

public function register()
{
    $this->app->singleton(TOTPAuthenticator::class, function ($app) {
        return new TOTPAuthenticator();
    });
}
```

## Basic Usage

### Generate a New Secret

```php
// Create a new TOTP authenticator instance with a randomly generated secret
$totp = new TOTPAuthenticator();

// Get and store the secret (you'll need to save this in your user database)
$secret = $totp->getSecret();
echo "Your TOTP secret: " . $secret;
```

### Verify a TOTP Code

```php
// Initialize with the user's stored secret
$totp = new TOTPAuthenticator($userSecret);

// Verify a code submitted by the user
$userInputCode = $_POST['totp_code']; // Example
if ($totp->verifyCode($userInputCode)) {
    echo "Code is valid!";
} else {
    echo "Invalid code!";
}
```

### Generate a QR Code URL

```php
$totp = new TOTPAuthenticator($userSecret);
$qrCodeUrl = $totp->getQRCodeUrl('user@example.com', 'My Application');

// You can use this URL with a QR code generation library
// Example with a CDN-based QR code generator:
echo "<img src='https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=" . urlencode($qrCodeUrl) . "&choe=UTF-8'>";
```

## Integration Examples

### Raw PHP Authentication Flow

```php
// User registration - generate and store secret
function registerUser($username, $password) {
    $totp = new TOTPAuthenticator();
    $secret = $totp->getSecret();
    
    // Hash password securely
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    // Store in database
    $db->query("INSERT INTO users (username, password_hash, totp_secret) 
                VALUES (?, ?, ?)", [$username, $passwordHash, $secret]);
                
    // Return QR code URL for setup
    return $totp->getQRCodeUrl($username, 'My Application');
}

// User login - validate password and TOTP code
function loginUser($username, $password, $totpCode) {
    // Fetch user from database
    $user = $db->query("SELECT * FROM users WHERE username = ?", [$username])->fetch();
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        return false; // Invalid username or password
    }
    
    // Verify TOTP code
    $totp = new TOTPAuthenticator($user['totp_secret']);
    if (!$totp->verifyCode($totpCode)) {
        return false; // Invalid TOTP code
    }
    
    // Authentication successful
    $_SESSION['user_id'] = $user['id'];
    return true;
}
```

### Laravel Integration Example

Here's how to integrate TOTP authentication with Laravel's built-in authentication:

#### Create a New Middleware

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use App\Services\Auth\TOTPAuthenticator;

class RequireTOTP
{
    public function handle($request, Closure $next)
    {
        $user = Auth::user();
        
        // Skip TOTP check if not enabled for this user
        if (!$user->totp_enabled) {
            return $next($request);
        }
        
        // Check if user has passed TOTP verification this session
        if (!session('totp_verified')) {
            return redirect()->route('totp.verify');
        }
        
        return $next($request);
    }
}
```

#### Create Controller Methods

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Services\Auth\TOTPAuthenticator;

class TOTPController extends Controller
{
    public function setup()
    {
        $user = auth()->user();
        
        // Generate new secret if user doesn't have one
        if (!$user->totp_secret) {
            $totp = new TOTPAuthenticator();
            $user->totp_secret = $totp->getSecret();
            $user->save();
        } else {
            $totp = new TOTPAuthenticator($user->totp_secret);
        }
        
        $qrCodeUrl = $totp->getQRCodeUrl($user->email, config('app.name'));
        
        return view('auth.totp.setup', [
            'secret' => $user->totp_secret,
            'qrCodeUrl' => $qrCodeUrl
        ]);
    }
    
    public function enable(Request $request)
    {
        $user = auth()->user();
        $totp = new TOTPAuthenticator($user->totp_secret);
        
        // Verify code before enabling TOTP
        if ($totp->verifyCode($request->code)) {
            $user->totp_enabled = true;
            $user->save();
            
            return redirect()->route('dashboard')
                ->with('status', 'Two-factor authentication has been enabled.');
        }
        
        return back()->withErrors(['code' => 'The verification code is invalid.']);
    }
    
    public function verify()
    {
        return view('auth.totp.verify');
    }
    
    public function validate(Request $request)
    {
        $user = auth()->user();
        $totp = new TOTPAuthenticator($user->totp_secret);
        
        if ($totp->verifyCode($request->code)) {
            // Mark session as TOTP verified
            session(['totp_verified' => true]);
            
            return redirect()->intended('dashboard');
        }
        
        return back()->withErrors(['code' => 'The verification code is invalid.']);
    }
}
```

#### Setup Routes

```php
Route::middleware(['auth'])->group(function () {
    Route::get('/totp/setup', [TOTPController::class, 'setup'])->name('totp.setup');
    Route::post('/totp/enable', [TOTPController::class, 'enable'])->name('totp.enable');
    Route::get('/totp/verify', [TOTPController::class, 'verify'])->name('totp.verify');
    Route::post('/totp/validate', [TOTPController::class, 'validate'])->name('totp.validate');
    
    // Apply TOTP middleware to protected routes
    Route::middleware(['require.totp'])->group(function () {
        Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
        // Add other protected routes here
    });
});
```

## Advanced Configuration

When creating a new `TOTPAuthenticator` instance, you can customize:

- **Digits**: The number of digits in the generated code (default: 6)
- **Time Step**: The time interval in seconds for which codes are valid (default: 30)

```php
// Create a TOTP authenticator with 8-digit codes and 60-second validity
$totp = new TOTPAuthenticator(null, 8, 60);
```

## Security Considerations

- Always store TOTP secrets securely in your database
- Use HTTPS to prevent man-in-the-middle attacks
- Consider implementing rate limiting to prevent brute-force attacks
- Provide backup codes in case users lose access to their authenticator app
- Use the `hash_equals()` function (as the class does internally) to prevent timing attacks

## Example Implementation with Backup Codes

```php
// Generate backup codes when setting up TOTP
function generateBackupCodes() {
    $codes = [];
    for ($i = 0; $i < 10; $i++) {
        $codes[] = substr(bin2hex(random_bytes(8)), 0, 10);
    }
    return $codes;
}

// Store hashed backup codes in database
$backupCodes = generateBackupCodes();
$hashedCodes = array_map(function($code) {
    return password_hash($code, PASSWORD_DEFAULT);
}, $backupCodes);

// Save $hashedCodes to database and show $backupCodes to user
```

## Requirements

- PHP 7.0 or higher
- OpenSSL extension for `random_bytes()` function

## License

This code is provided under the MIT License.
