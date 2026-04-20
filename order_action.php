<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

http_response_code(302);

$rootDir = dirname(__DIR__, 2);

$bootstrapCandidates = [
    $rootDir . '/bootstrap.php',
    $rootDir . '/config/bootstrap.php',
    $rootDir . '/config/init.php',
    $rootDir . '/includes/bootstrap.php',
    $rootDir . '/includes/init.php',
    $rootDir . '/public_html/bootstrap.php',
];

foreach ($bootstrapCandidates as $bootstrapFile) {
    if (is_file($bootstrapFile)) {
        require_once $bootstrapFile;
        break;
    }
}

$authCandidates = [
    $rootDir . '/seller/guard.php',
    $rootDir . '/seller/auth.php',
    $rootDir . '/includes/seller_guard.php',
    $rootDir . '/includes/seller_auth.php',
    $rootDir . '/public_html/seller/guard.php',
    $rootDir . '/public_html/seller/auth.php',
];
foreach ($authCandidates as $authFile) {
    if (is_file($authFile)) {
        require_once $authFile;
    }
}

$listingBootstrapCandidates = [
    $rootDir . '/seller/_listing_bootstrap.php',
    $rootDir . '/member/_listing_bootstrap.php',
];

foreach ($listingBootstrapCandidates as $listingBootstrapFile) {
    if (is_file($listingBootstrapFile)) {
        require_once $listingBootstrapFile;
        break;
    }
}

/**
 * @return PDO|null
 */
function resolve_pdo(): ?PDO
{
    $candidateKeys = ['pdo', 'db', 'conn', 'database'];

    foreach ($candidateKeys as $key) {
        if (isset($GLOBALS[$key]) && $GLOBALS[$key] instanceof PDO) {
            return $GLOBALS[$key];
        }
    }

    if (isset($GLOBALS['mysqli']) && $GLOBALS['mysqli'] instanceof PDO) {
        return $GLOBALS['mysqli'];
    }

    return null;
}

function current_seller_id(): int
{
    $candidates = [
        $_SESSION['user']['id'] ?? null,
        $_SESSION['seller']['id'] ?? null,
        $_SESSION['member']['id'] ?? null,
        $_SESSION['user_id'] ?? null,
        $_SESSION['seller_id'] ?? null,
        $_SESSION['seller']['id'] ?? null,
        $_SESSION['auth']['seller_id'] ?? null,
        $_SESSION['user']['seller_id'] ?? null,
    ];

    foreach ($candidates as $value) {
        if (is_numeric($value) && (int) $value > 0) {
            return (int) $value;
        }
    }

    return 0;
}

function set_flash(string $type, string $message): void
{
    $_SESSION['flash'] = [
        'type' => $type,
        'message' => $message,
    ];
}

function safe_return_url(string $candidate, int $orderId): string
{
    $fallback = '/seller/order_detail.php?id=' . $orderId;

    if ($candidate === '') {
        return $fallback;
    }

    if ($candidate[0] !== '/' || str_starts_with($candidate, '//')) {
        return $fallback;
    }

    if (preg_match('/[\r\n]/', $candidate)) {
        return $fallback;
    }

    return $candidate;
}

function redirect_to(string $url): void
{
    header('Location: ' . $url);
    exit;
}

$sellerId = current_seller_id();
if ($sellerId <= 0) {
    http_response_code(403);
    exit('Forbidden');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

$pdo = resolve_pdo();
if (!$pdo instanceof PDO) {
    set_flash('error', 'Database connection unavailable.');
    redirect_to('/seller/orders.php');
}

$action = (string) ($_POST['action'] ?? '');
$orderItemId = (int) ($_POST['order_item_id'] ?? 0);
$trackingNumber = trim((string) ($_POST['tracking_number'] ?? ''));
$carrier = trim((string) ($_POST['carrier'] ?? ''));
$csrfToken = (string) ($_POST['csrf_token'] ?? '');
$returnUrlInput = (string) ($_POST['return_url'] ?? '');

$sessionCsrfTokens = [];

if (isset($_SESSION['csrf_token']) && is_string($_SESSION['csrf_token']) && $_SESSION['csrf_token'] !== '') {
    $sessionCsrfTokens[] = $_SESSION['csrf_token'];
}

foreach ($_SESSION as $sessionKey => $sessionValue) {
    if (
        is_string($sessionKey)
        && str_starts_with($sessionKey, '_csrf_')
        && is_string($sessionValue)
        && $sessionValue !== ''
    ) {
        $sessionCsrfTokens[] = $sessionValue;
    }
}

if ($sessionCsrfTokens !== []) {
    $csrfValid = false;

    foreach (array_values(array_unique($sessionCsrfTokens)) as $expectedCsrfToken) {
        if ($csrfToken !== '' && hash_equals($expectedCsrfToken, $csrfToken)) {
            $csrfValid = true;
            break;
        }
    }

    if (!$csrfValid) {
        set_flash('error', 'Invalid security token.');
        redirect_to('/seller/orders.php');
    }
}

if ($orderItemId <= 0) {
    set_flash('error', 'Invalid order item.');
    redirect_to('/seller/orders.php');
}

$transitions = [
    'mark_processing' => ['from' => 'pending', 'to' => 'processing'],
    'mark_shipped' => ['from' => 'processing', 'to' => 'shipped'],
    'mark_completed' => ['from' => 'shipped', 'to' => 'completed'],
];

if (!isset($transitions[$action])) {
    set_flash('error', 'Unsupported action.');
    redirect_to('/seller/orders.php');
}

try {
    $pdo->beginTransaction();

    $sql = 'SELECT oi.id, oi.order_id, oi.fulfillment_status, l.seller_id
            FROM order_items oi
            INNER JOIN listings l ON l.id = oi.listing_id
            WHERE oi.id = :order_item_id
            LIMIT 1
            FOR UPDATE';
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':order_item_id' => $orderItemId]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$item) {
        $pdo->rollBack();
        set_flash('error', 'Order item not found.');
        redirect_to('/seller/orders.php');
    }

    $orderId = (int) $item['order_id'];

    if ((int) $item['seller_id'] !== $sellerId) {
        $pdo->rollBack();
        set_flash('error', 'You are not allowed to update this item.');
        redirect_to(safe_return_url($returnUrlInput, $orderId));
    }

    $oldStatus = (string) $item['fulfillment_status'];
    $newStatus = $transitions[$action]['to'];
    $requiredCurrent = $transitions[$action]['from'];

    if ($oldStatus !== $requiredCurrent || in_array($oldStatus, ['cancelled', 'completed'], true)) {
        $pdo->rollBack();
        set_flash('error', 'Invalid status transition.');
        redirect_to(safe_return_url($returnUrlInput, $orderId));
    }

    if ($action === 'mark_shipped' && $trackingNumber === '') {
        $pdo->rollBack();
        set_flash('error', 'Tracking number is required to mark as shipped.');
        redirect_to(safe_return_url($returnUrlInput, $orderId));
    }

    if ($action === 'mark_processing') {
        $updateSql = 'UPDATE order_items
                      SET fulfillment_status = :new_status,
                          processed_at = NOW()
                      WHERE id = :order_item_id';
        $updateParams = [
            ':new_status' => $newStatus,
            ':order_item_id' => $orderItemId,
        ];
    } elseif ($action === 'mark_shipped') {
        $updateSql = 'UPDATE order_items
                      SET fulfillment_status = :new_status,
                          shipped_at = NOW(),
                          tracking_number = :tracking_number,
                          carrier = :carrier
                      WHERE id = :order_item_id';
        $updateParams = [
            ':new_status' => $newStatus,
            ':tracking_number' => $trackingNumber,
            ':carrier' => $carrier !== '' ? $carrier : null,
            ':order_item_id' => $orderItemId,
        ];
    } else {
        $updateSql = 'UPDATE order_items
                      SET fulfillment_status = :new_status,
                          completed_at = NOW()
                      WHERE id = :order_item_id';
        $updateParams = [
            ':new_status' => $newStatus,
            ':order_item_id' => $orderItemId,
        ];
    }

    $updateStmt = $pdo->prepare($updateSql);
    $updateStmt->execute($updateParams);

    $logSql = 'INSERT INTO order_item_logs
               (order_item_id, action, old_status, new_status, actor_type, actor_id, created_at)
               VALUES
               (:order_item_id, :action, :old_status, :new_status, :actor_type, :actor_id, NOW())';
    $logStmt = $pdo->prepare($logSql);
    $logStmt->execute([
        ':order_item_id' => $orderItemId,
        ':action' => $action,
        ':old_status' => $oldStatus,
        ':new_status' => $newStatus,
        ':actor_type' => 'seller',
        ':actor_id' => $sellerId,
    ]);

    $aggregateSql = 'SELECT
                        COUNT(*) AS total_items,
                        SUM(CASE WHEN fulfillment_status = "completed" THEN 1 ELSE 0 END) AS completed_items,
                        SUM(CASE WHEN fulfillment_status IN ("shipped", "completed") THEN 1 ELSE 0 END) AS shipped_or_completed_items,
                        SUM(CASE WHEN fulfillment_status IN ("processing", "shipped", "completed") THEN 1 ELSE 0 END) AS progressed_items
                     FROM order_items
                     WHERE order_id = :order_id';
    $aggStmt = $pdo->prepare($aggregateSql);
    $aggStmt->execute([':order_id' => $orderId]);
    $agg = $aggStmt->fetch(PDO::FETCH_ASSOC) ?: [];

    $orderStatusStmt = $pdo->prepare('SELECT status FROM orders WHERE id = :order_id LIMIT 1 FOR UPDATE');
    $orderStatusStmt->execute([':order_id' => $orderId]);
    $currentOrderStatus = (string) ($orderStatusStmt->fetchColumn() ?: '');

    $totalItems = (int) ($agg['total_items'] ?? 0);
    $completedItems = (int) ($agg['completed_items'] ?? 0);
    $shippedOrCompletedItems = (int) ($agg['shipped_or_completed_items'] ?? 0);
    $progressedItems = (int) ($agg['progressed_items'] ?? 0);

    $derivedStatus = null;
    if ($totalItems > 0 && $completedItems === $totalItems) {
        $derivedStatus = 'completed';
    } elseif ($totalItems > 0 && $shippedOrCompletedItems === $totalItems) {
        $derivedStatus = 'shipped';
    } elseif ($progressedItems > 0) {
        $derivedStatus = 'processing';
    }

    if ($derivedStatus !== null) {
        $rank = [
            'pending' => 0,
            'confirmed' => 0,
            'paid' => 0,
            'processing' => 1,
            'shipped' => 2,
            'completed' => 3,
        ];

        $currentRank = $rank[$currentOrderStatus] ?? -1;
        $derivedRank = $rank[$derivedStatus] ?? -1;

        if ($derivedRank > $currentRank) {
            $updateOrderStatusStmt = $pdo->prepare('UPDATE orders SET status = :status WHERE id = :order_id');
            $updateOrderStatusStmt->execute([
                ':status' => $derivedStatus,
                ':order_id' => $orderId,
            ]);
        }
    }

    $pdo->commit();

    set_flash('success', 'Order item updated successfully.');
    redirect_to(safe_return_url($returnUrlInput, $orderId));
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    set_flash('error', 'Unable to process order action.');
    redirect_to('/seller/orders.php');
}
