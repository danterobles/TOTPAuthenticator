# TOTP Authenticator for PHP

## Overview

`TOTPAuthenticator` is a PHP class that implements Time-based One-Time Password (TOTP) authentication according to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). It provides a secure way to implement two-factor authentication (2FA) in your PHP applications, compatible with popular authenticator apps like Google Authenticator, Microsoft Authenticator, and Authy.

## Features

- Generate secure random secrets for TOTP authentication (minimum 128 bits / 16 bytes)
- Create and validate time-based one-time passwords
- Generate QR code URLs for easy setup with authenticator apps
- Generate backup codes for account recovery
- Input validation with descriptive exceptions for invalid configuration
- Customizable code length (6–8 digits) and time step
- Built-in Base32 encoding/decoding
- Full PHP 7.4+ type hints on all properties and methods
- Compatible with all standard TOTP authenticator applications

## Requirements

- PHP 7.4 or higher
- OpenSSL extension (for `random_bytes()`)

## Installation

### Raw PHP

Simply include the `TOTPAuthenticator.php` file in your project:

```php
require_once 'path/to/TOTPAuthenticator.php';
```

### Composer / Laravel

Install via Composer:

```bash
composer require danterobles/totp-authenticator
```

Or copy `src/TOTPAuthenticator.php` to your Laravel project and update the namespace:

```php
<?php

namespace App\Services\Auth;

class TOTPAuthenticator
{
    // Class content remains the same
}
```

Optionally register it as a singleton in `AppServiceProvider`:

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
use TOTP\TOTPAuthenticator;

// Generates a cryptographically secure random secret (20 bytes / 160 bits by default)
$totp = new TOTPAuthenticator();

// Store this secret in your user database
$secret = $totp->getSecret();
echo "Your TOTP secret: " . $secret;
```

### Verify a TOTP Code

```php
use TOTP\TOTPAuthenticator;

// Initialize with the user's stored secret
$totp = new TOTPAuthenticator($userSecret);

$userInputCode = $_POST['totp_code'];
if ($totp->verifyCode($userInputCode)) {
    echo "Code is valid!";
} else {
    echo "Invalid code!";
}
```

### Generate a QR Code URL

```php
use TOTP\TOTPAuthenticator;

$totp = new TOTPAuthenticator($userSecret);
$qrCodeUrl = $totp->getQRCodeUrl('user@example.com', 'My Application');

// Use with any QR code generation library
echo "<img src='https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=" . urlencode($qrCodeUrl) . "&choe=UTF-8'>";
```

### Generate Backup Codes

```php
use TOTP\TOTPAuthenticator;

$totp = new TOTPAuthenticator($userSecret);

// Returns an array of plain-text backup codes
$backupCodes = $totp->generateBackupCodes(count: 10, length: 10);

// Show plain codes once to the user, then store only the hashed versions
$hashedCodes = array_map(fn($code) => password_hash($code, PASSWORD_DEFAULT), $backupCodes);

// Save $hashedCodes to database
```

## Advanced Configuration

The constructor accepts optional parameters to customize code generation:

```php
// 8-digit codes valid for 60 seconds
$totp = new TOTPAuthenticator(secret: null, digits: 8, timeStep: 60);
```

| Parameter | Type | Default | Constraints |
|-----------|------|---------|-------------|
| `$secret` | `?string` | `null` (auto-generated) | Valid Base32, min 128 bits decoded |
| `$digits` | `int` | `6` | Must be between 6 and 8 |
| `$timeStep` | `int` | `30` | Must be a positive integer |

Invalid values throw `\InvalidArgumentException` with a descriptive message.

## Integration Examples

### Raw PHP Authentication Flow

```php
use TOTP\TOTPAuthenticator;

function registerUser(string $username, string $password): string
{
    $totp = new TOTPAuthenticator();
    $secret = $totp->getSecret();

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $db->query(
        "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
        [$username, $passwordHash, $secret]
    );

    return $totp->getQRCodeUrl($username, 'My Application');
}

function loginUser(string $username, string $password, string $totpCode): bool
{
    $user = $db->query("SELECT * FROM users WHERE username = ?", [$username])->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        return false;
    }

    $totp = new TOTPAuthenticator($user['totp_secret']);

    if (!$totp->verifyCode($totpCode)) {
        return false;
    }

    $_SESSION['user_id'] = $user['id'];
    return true;
}
```

### Laravel Integration Example

#### Middleware

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

        if (!$user->totp_enabled) {
            return $next($request);
        }

        if (!session('totp_verified')) {
            return redirect()->route('totp.verify');
        }

        return $next($request);
    }
}
```

#### Controller

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

        if (!$user->totp_secret) {
            $totp = new TOTPAuthenticator();
            $user->totp_secret = $totp->getSecret();
            $user->save();
        } else {
            $totp = new TOTPAuthenticator($user->totp_secret);
        }

        return view('auth.totp.setup', [
            'secret'     => $user->totp_secret,
            'qrCodeUrl'  => $totp->getQRCodeUrl($user->email, config('app.name')),
            'backupCodes' => $totp->generateBackupCodes(),
        ]);
    }

    public function enable(Request $request)
    {
        $user = auth()->user();
        $totp = new TOTPAuthenticator($user->totp_secret);

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
            session(['totp_verified' => true]);
            return redirect()->intended('dashboard');
        }

        return back()->withErrors(['code' => 'The verification code is invalid.']);
    }
}
```

#### Routes

```php
Route::middleware(['auth'])->group(function () {
    Route::get('/totp/setup',    [TOTPController::class, 'setup'])->name('totp.setup');
    Route::post('/totp/enable',  [TOTPController::class, 'enable'])->name('totp.enable');
    Route::get('/totp/verify',   [TOTPController::class, 'verify'])->name('totp.verify');
    Route::post('/totp/validate', [TOTPController::class, 'validate'])->name('totp.validate');

    Route::middleware(['require.totp'])->group(function () {
        Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    });
});
```

## Security Considerations

- Always store TOTP secrets securely in your database (consider encrypting at rest)
- Store backup codes **hashed** (e.g. `password_hash()`), never in plain text
- Use HTTPS to prevent man-in-the-middle attacks
- Implement rate limiting to prevent brute-force attacks
- The class uses `hash_equals()` internally to prevent timing attacks
- Secrets must be at least 128 bits (16 decoded bytes) — enforced by the constructor

## License

This code is provided under the MIT License.
