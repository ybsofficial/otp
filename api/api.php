<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: ' . ($_SERVER['HTTP_ORIGIN'] ?? '*'));
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-KEY');
    http_response_code(200);
    exit;
}

session_start();

error_reporting(E_ALL);
ini_set('display_errors', 1);

// --- CONFIGURATION ---
$DB_FILE = 'database.json';
$LOG_FILE = 'logs.json';
$KEY_JASA_OTP = "e50bc513e4fc8700b39b77574a73c6bc";
$KEY_ATLANTIC = "cIr6yFSfNiCtzfOw50IIb8xvviGlG4U9o7wLe60Pvrz9os0Ff0ARoAMKdNj7YyqVYi25YtfQoyGVlPo8ce3wAuawklZJlqJF6mmN";
$BASE_URL_ATLANTIC = "https://atlantich2h.com";

// --- OWNER CONFIG ---
$OWNER_USER = "jarr";
$OWNER_PASS = "owner"; 

// --- TELEGRAM CONFIG ---
$TELE_TOKEN = "8406572685:AAFZM802DOlHUbB0McQnrREmgFOH4o5p-BI";
$TELE_CHAT_ID = "-1003648588091";

// --- DATABASE FUNCTIONS ---
function get_db() {
    global $DB_FILE;

    if (!file_exists($DB_FILE)) {
        $initial = [
            'users' => [],
            'processed_deposits' => [],
            'maintenance' => false
        ];
        file_put_contents(
            $DB_FILE,
            json_encode($initial, JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    $json = file_get_contents($DB_FILE);
    $data = json_decode($json, true);

    if (!is_array($data)) {
        $data = [
            'users' => [],
            'processed_deposits' => [],
            'maintenance' => false
        ];
    }

    if (!isset($data['users']) || !is_array($data['users'])) {
        $data['users'] = [];
    }

    return $data;
}

function save_db($data) {
    global $DB_FILE;

    file_put_contents(
        $DB_FILE,
        json_encode($data, JSON_PRETTY_PRINT),
        LOCK_EX
    );
}

function saveToLog($data) {
    global $LOG_FILE;

    $logs = [];

    if (file_exists($LOG_FILE)) {
        $logs = json_decode(file_get_contents($LOG_FILE), true);
        if (!is_array($logs)) $logs = [];
    }

    array_unshift($logs, $data);

    if (count($logs) > 20) {
        $logs = array_slice($logs, 0, 20);
    }

    file_put_contents(
        $LOG_FILE,
        json_encode($logs, JSON_PRETTY_PRINT),
        LOCK_EX
    );
}

// Tambahkan fungsi ini di api.php
function user_exists($db, $username, $email) {
    // Cek apakah username sudah ada
    if (isset($db['users'][$username])) {
        return true;
    }
    // Cek apakah email sudah digunakan oleh user lain
    foreach ($db['users'] as $u) {
        if (isset($u['email']) && $u['email'] === $email) {
            return true;
        }
    }
    return false;
}

function get_jasaotp_balance() {
    global $KEY_JASA_OTP;
    // Memanggil API JasaOTP untuk cek saldo akun pusat
    $res = call("https://api.jasaotp.id/v1/balance.php?api_key=" . $KEY_JASA_OTP);
    return json_decode($res, true);
}

function get_atlantic_balance() {
    $res = callAtlantic('/get_profile');
    return json_decode($res, true);
}

function sendTelegram($message) {
    global $TELE_TOKEN, $TELE_CHAT_ID;
    $footer = "\n\n🛒 *Order Sekarang di:* https://jasa-otp.wuaze.com";
    $full_message = $message . $footer;
    $url = "https://api.telegram.org/bot$TELE_TOKEN/sendMessage";
    $data = [
        'chat_id' => $TELE_CHAT_ID,
        'text' => $full_message,
        'parse_mode' => 'Markdown',
        'disable_web_page_preview' => false 
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($ch);
    curl_close($ch);
}

function callAtlantic($endpoint, $postData = []) {
    global $KEY_ATLANTIC, $BASE_URL_ATLANTIC;
    
    $url = $BASE_URL_ATLANTIC . $endpoint;
    $postData['api_key'] = $KEY_ATLANTIC; // Otomatis selipkan API Key

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData)); // Format x-www-form-urlencoded
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    $res = curl_exec($ch);
    curl_close($ch);
    return $res;
}

function call($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    $res = curl_exec($ch);
    if(curl_errno($ch)) {
        return json_encode(["success" => false, "message" => "Curl Error: " . curl_error($ch)]);
    }
    curl_close($ch);
    return $res;
}

function generateApiKey() {
    // Membuat 8 karakter acak (huruf & angka)
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < 8; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    
    // Hasilnya akan jadi: jasaotp-A1b2C3d4
    return "jasaotp-" . $randomString;
}

// --- GATEWAY & SESSION AUTH (REVISED) ---
$db = get_db();
$action = $_GET['action'] ?? '';

// 1. Ambil API Key dari berbagai kemungkinan input
$api_key_input = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? $_POST['api_key'] ?? null;

// 2. Tentukan currentUser (prioritas: Session, lalu API Key)
$currentUser = $_SESSION['username'] ?? null;

if (!$currentUser && $api_key_input) {
    foreach ($db['users'] as $username => $u_data) {
        if (isset($u_data['api_key']) && $u_data['api_key'] === $api_key_input) {
            $currentUser = $username;
            $_SESSION['username'] = $username; // Set sesi agar permintaan berikutnya lebih cepat
            break;
        }
    }
}

// 3. Proteksi Akses: Izinkan hanya login/register jika tidak ada user
$public_actions = ['login', 'register'];
if (!in_array($action, $public_actions) && !$currentUser) {
    http_response_code(401); // Set kode status Unauthorized
    die(json_encode([
        "success" => false, 
        "message" => "Akses ditolak. API Key tidak valid atau sesi berakhir."
    ]));
}

// 3. LOGIKA ROLE (Jika user login sebagai owner)
$isOwner = (isset($_SESSION['role']) && $_SESSION['role'] === 'owner') || ($currentUser === $OWNER_USER);

switch($action) {
    // === AUTHENTICATION ===
        case 'check_user': // Samakan dengan panggilan di daftar.html
    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');

    if ($username === '' || $email === '') {
        echo json_encode(['success' => false, 'message' => 'Data tidak lengkap']);
        exit;
    }

    if (user_exists($db, $username, $email)) {
        echo json_encode(['success' => false, 'message' => 'Username atau email sudah terdaftar']);
    } else {
        echo json_encode(['success' => true, 'message' => 'Data tersedia']);
    }
    exit;

        case 'register':

    $user  = trim($_POST['username'] ?? '');
    $pass  = trim($_POST['password'] ?? '');
    $email = trim($_POST['email'] ?? '');

    if ($user === '' || $pass === '' || $email === '') {
        echo json_encode(['success'=>false,'message'=>'Data tidak lengkap']);
        exit;
    }

    if (user_exists($db, $user, $email)) {
        echo json_encode(['success'=>false,'message'=>'Username atau email sudah terdaftar']);
        exit;
    }

    $hash = function_exists('password_hash')
        ? password_hash($pass, PASSWORD_DEFAULT)
        : md5($pass);

    $apiKey = function_exists('random_bytes')
        ? bin2hex(random_bytes(16))
        : md5(uniqid(rand(), true));

    $db['users'][$user] = [
        'password' => $hash,
        'email'    => $email,
        'saldo'    => 0,
        'status'   => 'active',
        'api_key'  => $apiKey
    ];

    save_db($db);

    echo json_encode(['success'=>true,'message'=>'Akun berhasil dibuat']);
    exit;

    case 'change_password':
        if (!$currentUser) die(json_encode(['success' => false, 'message' => 'Silakan login kembali']));
        $json_input = json_decode(file_get_contents('php://input'), true);
        $old_pass = $json_input['old'] ?? '';
        $new_pass = $json_input['new'] ?? '';
        if ($db['users'][$currentUser]['password'] === $old_pass) {
            $db['users'][$currentUser]['password'] = $new_pass;
            save_db($db);
            session_destroy();
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Password lama salah']);
        }
        break;

    case 'login':
        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';
        if(($db['maintenance'] ?? false) && $user !== $OWNER_USER) {
            die(json_encode(["success" => false, "message" => "Sistem sedang MAINTENANCE"]));
        }
        if($user === $OWNER_USER && $pass === $OWNER_PASS) {
            $_SESSION['username'] = $user; $_SESSION['role'] = 'owner';
            echo json_encode(["success" => true, "role" => "owner"]);
            break;
        }
        if(isset($db['users'][$user]) && $db['users'][$user]['password'] === $pass) {
            if(($db['users'][$user]['status'] ?? '') === 'banned') die(json_encode(["success" => false, "message" => "Akun Anda di-BANNED"]));
            
            // Generate API Key if not exists (for old users)
            if(!isset($db['users'][$user]['api_key'])) {
                $db['users'][$user]['api_key'] = generateApiKey();
                save_db($db);
            }
            
            $_SESSION['username'] = $user; $_SESSION['role'] = 'user';
            echo json_encode(["success" => true, "role" => "user", "api_key" => $db['users'][$user]['api_key']]);
        } else { echo json_encode(["success" => false, "message" => "Username/Password salah"]); }
        break;

    case 'get_profile':
    if(!$currentUser) {
        http_response_code(401);
        die(json_encode(["success" => false, "message" => "Sesi berakhir"]));
    }
    
    // Cek jika API Key belum ada di database, buatkan otomatis
    if(!isset($db['users'][$currentUser]['api_key']) || empty($db['users'][$currentUser]['api_key'])) {
        $db['users'][$currentUser]['api_key'] = generateApiKey();
        save_db($db);
    }

    echo json_encode([
        "success" => true, 
        "data" => [
            "username" => $currentUser, 
            "saldo" => $db['users'][$currentUser]['saldo'] ?? 0,
            "api_key" => $db['users'][$currentUser]['api_key'] 
        ]
    ]);
    break;

        case 'get_admin_stats':
    if(($_SESSION['role'] ?? '') !== 'owner') die(json_encode(["success" => false]));
    
    // 1. Ambil saldo JasaOTP
    $jasaotp = get_jasaotp_balance();
    $saldo_jasaotp = (isset($jasaotp['success']) && $jasaotp['success']) ? $jasaotp['data']['saldo'] : 0;

    // 2. Ambil saldo Atlantic
    $atlantic = get_atlantic_balance();
    $saldo_atlantic = (isset($atlantic['status']) && $atlantic['status'] == "true") ? $atlantic['data']['balance'] : 0;

    echo json_encode([
        "success" => true, 
        "maintenance" => $db['maintenance'] ?? false, 
        "users" => $db['users'], 
        "stats" => [
            "total_user" => count($db['users']), 
            "total_depo" => count($db['processed_deposits']),
            "saldo_jasaotp" => $saldo_jasaotp,
            "saldo_atlantic" => $saldo_atlantic
        ]
    ]);
    break;

    case 'reset_api_key':
        if(!$currentUser) die(json_encode(["success" => false]));
        $newKey = generateApiKey();
        $db['users'][$currentUser]['api_key'] = $newKey;
        save_db($db);
        echo json_encode(["success" => true, "api_key" => $newKey]);
        break;

    // === TRANSFER SALDO SYSTEM ===
    case 'transfer_saldo':
        if(!$currentUser) die(json_encode(["success" => false, "message" => "Login dahulu"]));
        $data = json_decode(file_get_contents('php://input'), true);
        $target_username = $data['target_username'] ?? '';
        $amount = (int)($data['amount'] ?? 0);
        if (empty($target_username) || $amount < 1000) die(json_encode(['success' => false, 'message' => 'Min. transfer Rp 1.000']));
        if ($target_username === $currentUser) die(json_encode(['success' => false, 'message' => 'Tidak bisa transfer ke diri sendiri']));
        if (!isset($db['users'][$target_username])) die(json_encode(['success' => false, 'message' => 'Username penerima tidak ditemukan']));
        if (($db['users'][$currentUser]['saldo'] ?? 0) < $amount) die(json_encode(['success' => false, 'message' => 'Saldo Anda tidak mencukupi']));
        
        $db['users'][$currentUser]['saldo'] -= $amount;
        $db['users'][$target_username]['saldo'] += $amount;
        save_db($db);
        $tgl = date('d M Y, H.i');
        saveToLog(["type"=>"transfer", "from"=>$currentUser, "to"=>$target_username, "amount"=>number_format($amount), "date"=>$tgl]);
        sendTelegram("💸 *TRANSFER BERHASIL !!*\n\nDari: *$currentUser*\nKe: *$target_username*\nNominal: *Rp " . number_format($amount) . "*");
        echo json_encode(['success' => true, 'message' => 'Transfer berhasil']);
        break;

    // === JASA OTP SERVICES (V1) ===
    case 'get_negara': echo call("https://api.jasaotp.id/v1/negara.php"); break;
    case 'get_operator': echo call("https://api.jasaotp.id/v1/operator.php?negara=".$_GET['negara']); break;
    case 'get_layanan': echo call("https://api.jasaotp.id/v1/layanan.php?negara=".$_GET['negara']); break;

    case 'order_nomor':
        if(!isset($_SESSION['username'])) die(json_encode(["success" => false, "message" => "Login dahulu"]));
        $user = $_SESSION['username']; $db = get_db();
        $neg = $_GET['negara'] ?? ''; $lay = $_GET['layanan'] ?? ''; $op = $_GET['operator'] ?? ''; $harga = (int)($_GET['harga'] ?? 0);
        if($db['users'][$user]['saldo'] < $harga) die(json_encode(["success" => false, "message" => "Saldo kurang"]));
        $res = call("https://api.jasaotp.id/v1/order.php?api_key=$KEY_JASA_OTP&negara=$neg&layanan=$lay&operator=$op");
        $data = json_decode($res, true);
        if(isset($data['success']) && $data['success']) {
            $db['users'][$user]['saldo'] -= $harga;
            save_db($db);
        }
        echo $res;
        break;

    case 'cek_sms':
        $id = $_GET['id'] ?? '';
        $user = $_SESSION['username'] ?? 'Guest';
        $res = call("https://api.jasaotp.id/v1/sms.php?api_key=$KEY_JASA_OTP&id=$id");
        $data = json_decode($res, true);
        if (isset($data['data']['otp'])) {
            $otp_raw = $data['data']['otp'];
            if (strpos(strtolower($otp_raw), 'menunggu') !== false || empty($otp_raw)) {
                echo json_encode(["success" => false, "message" => "OTP masih menunggu"]);
            } else {
                $tgl = date('d M Y, H.i');
                $price = number_format($data['data']['price'] ?? 0);
                $msg = "🔐 *OTP RECEIVED !!*\n\nID: `$id`\nUsers: *$user*\nNumber: `".$data['data']['number']."`\nSMS code: `".$otp_raw."`\nHarga: Rp$price\nTanggal: $tgl";
                sendTelegram($msg);
                saveToLog(["type"=>"otp", "id"=>$id, "username"=>$user, "number"=>$data['data']['number'], "otp"=>$otp_raw, "price"=>$price, "date"=>$tgl, "full_sms"=>$data['data']['sms']]);
                echo $res;
            }
        } else { echo $res; }
        break;

    case 'cancel_nomor':
        $id = $_GET['id'] ?? ''; $user = $_SESSION['username'] ?? '';
        $res = call("https://api.jasaotp.id/v1/cancel.php?api_key=$KEY_JASA_OTP&id=$id");
        $data = json_decode($res, true);
        if(isset($data['success']) && $data['success']) {
            $db = get_db(); $refund = (int)($data['data']['refunded_amount'] ?? 0);
            if($user && isset($db['users'][$user])) { $db['users'][$user]['saldo'] += $refund; save_db($db); }
        }
        echo $res;
        break;

    // === RUMAH OTP V2 ===
    case 'get_services': echo call("$BASE_URL_RUMAH/v2/services", true); break;
    case 'get_countries': echo call("$BASE_URL_RUMAH/v2/countries?service_id=".($_GET['service_id'] ?? ''), true); break;
    case 'get_operators': echo call("$BASE_URL_RUMAH/v2/operators?country=".urlencode($_GET['country'] ?? '')."&service_id=".($_GET['service_id'] ?? ''), true); break;

    case 'order_nomor_v2':
        if(!$currentUser) die(json_encode(["success" => false, "message" => "Login dahulu"]));
        $numId = $_GET['number_id'] ?? ''; $opId = $_GET['operator_id'] ?? ''; $harga = (int)($_GET['harga'] ?? 0);
        if($db['users'][$currentUser]['saldo'] < $harga) die(json_encode(["success" => false, "message" => "Saldo tidak cukup"]));
        $res = call("$BASE_URL_RUMAH/v2/orders?number_id=$numId&provider_id=3837&operator_id=$opId", true);
        $data = json_decode($res, true);
        if(isset($data['success']) && $data['success']) {
            $db['users'][$currentUser]['saldo'] -= $harga;
            save_db($db);
        }
        echo $res;
        break;

    case 'get_status_v2':
        $orderId = $_GET['order_id'] ?? '';
        echo call("$BASE_URL_RUMAH/v1/orders/get_status?order_id=$orderId", true);
        break;

    case 'cancel_order_v2':
        $orderId = $_GET['order_id'] ?? '';
        echo call("$BASE_URL_RUMAH/v1/orders/set_status?order_id=$orderId&status=cancel", true);
        break;

        // === ATLANTIC DEPOSIT SYSTEM ===

    case 'get_deposit_methods':
        // Mengambil daftar metode pembayaran (bank/ewallet/va)
        $type = $_GET['type'] ?? 'ewallet'; 
        echo callAtlantic('/deposit/metode', ['type' => $type]);
        break;

    case 'create_deposit':
        if(!$currentUser) die(json_encode(["success" => false, "message" => "Login dahulu"]));
        
        $nominal = $_GET['amount'] ?? 0;
        $type = $_GET['type'] ?? 'ewallet'; // bank, ewallet, atau va
        $metode = $_GET['metode'] ?? 'qris';
        $reff_id = "DEP" . time() . rand(100, 999);

        $res = callAtlantic('/deposit/create', [
            'reff_id' => $reff_id,
            'nominal' => $nominal,
            'type' => $type,
            'metode' => $metode
        ]);

        $data = json_decode($res, true);
        if(isset($data['status']) && $data['status']) {
            $_SESSION['active_deposit'] = $data['data'];
        }
        echo $res;
        break;

        case 'cek_deposit':
        $id = $_GET['id'] ?? '';
        if(!$currentUser) die(json_encode(["success" => false, "message" => "Auth Failed"]));

        // 1. Cek Status Dulu
        $res = callAtlantic('/deposit/status', ['id' => $id]);
        $data = json_decode($res, true);

        if(isset($data['status']) && $data['status']) {
            $status = strtolower($data['data']['status']);
            $amount = (int)$data['data']['get_balance']; 

            // 2. Jika status 'processing', tembak endpoint instant agar jadi 'success'
            if($status === 'processing') {
                $resInstant = callAtlantic('/deposit/instant', ['id' => $id, 'action' => 'true']);
                $dataInstant = json_decode($resInstant, true);
                if(isset($dataInstant['status']) && $dataInstant['status']) {
                    $status = 'success'; 
                }
            }

            // 3. Jika status success, tambahkan saldo dan simpan ke LOG
            if($status === 'success') {
                if (!in_array($id, $db['processed_deposits'])) {
                    // Update Saldo User
                    $db['users'][$currentUser]['saldo'] += $amount;
                    $db['processed_deposits'][] = $id;
                    save_db($db);
                    
                    // --- BAGIAN PERBAIKAN: CATAT KE LIVE LOG ---
                    $tgl = date('d M Y, H.i');
                    saveToLog([
                        "type" => "deposit", 
                        "username" => $currentUser, 
                        "amount" => number_format($amount), 
                        "date" => $tgl
                    ]);
                    // -------------------------------------------
                    
                    sendTelegram("💰 *DEPOSIT BERHASIL (ATLANTIC)*\n\nUser: *$currentUser*\nNominal: *Rp " . number_format($amount) . "*\nMetode: " . $data['data']['metode']);
                    unset($_SESSION['active_deposit']);
                    
                    echo json_encode(["success" => true, "message" => "Saldo berhasil ditambahkan", "status" => "success"]);
                } else {
                    echo json_encode(["success" => false, "message" => "Deposit sudah pernah diproses"]);
                }
            } else {
                echo $res; 
            }
        } else {
            echo $res;
        }
        break;

    case 'cancel_deposit':
        $id = $_GET['id'] ?? '';
        $res = callAtlantic('/deposit/cancel', ['id' => $id]);
        unset($_SESSION['active_deposit']);
        echo $res;
        break;

    // === ADMIN & CORE ===
    case 'get_admin_stats':
        if(($_SESSION['role'] ?? '') !== 'owner') die(json_encode(["success" => false]));
        echo json_encode(["success" => true, "maintenance" => $db['maintenance'] ?? false, "users" => $db['users'], "stats" => ["total_user" => count($db['users']), "total_depo" => count($db['processed_deposits'])]]);
        break;

    case 'manage_user':
        if(($_SESSION['role'] ?? '') !== 'owner') die();
        $target = $_POST['target_user']; $type = $_POST['type']; $val = (int)($_POST['value'] ?? 0);
        if(!isset($db['users'][$target])) die();
        if($type == 'add_saldo') $db['users'][$target]['saldo'] += $val;
        if($type == 'reduce_saldo') $db['users'][$target]['saldo'] -= $val;
        if($type == 'banned') $db['users'][$target]['status'] = 'banned';
        if($type == 'unbanned') $db['users'][$target]['status'] = 'active';
        save_db($db);
        echo json_encode(["success" => true]);
        break;

    case 'get_active_deposit':
        echo isset($_SESSION['active_deposit']) ? json_encode(["success" => true, "data" => $_SESSION['active_deposit']]) : json_encode(["success" => false]);
        break;

    case 'get_live_logs':
        echo json_encode(["success" => true, "data" => file_exists($LOG_FILE) ? json_decode(file_get_contents($LOG_FILE), true) : []]);
        break;

    case 'toggle_maintenance':
        if(($_SESSION['role'] ?? '') !== 'owner') die();
        $db = get_db();
        $db['maintenance'] = !($db['maintenance'] ?? false);
        save_db($db);
        echo json_encode(["success" => true, "maintenance" => $db['maintenance']]);
        break;

    default: echo json_encode(["success" => false, "message" => "Action not found"]); break;
}
