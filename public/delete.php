<?php

require '../config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$time = @$_POST['time'];
$id = @$_POST['id'];
$signature = @$_POST['signature'];

if (!isset($time) || !isset($id) || !isset($signature)) {
    http_response_code(400);
    exit;
}

if ($signature !== hash_hmac('sha256', $time.$id, OM_SECRET_KEY)) {
    http_response_code(401);
    exit;
}

if (time() >= $time + 30) {
    http_response_code(401);
    exit;
}

$blobPath = __DIR__.'/../storage/'.$id.'.blob';
$metaPath = __DIR__.'/../storage/'.$id.'.meta';

if (file_exists($blobPath)) {
    @unlink($blobPath);
}

if (file_exists($metaPath)) {
    @unlink($metaPath);
}

if (file_exists($blobPath) || file_exists($metaPath)) {
    http_response_code(500);
    exit;
}

http_response_code(200);
exit;
