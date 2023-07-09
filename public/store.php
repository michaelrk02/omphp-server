<?php

require '../config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$time = @$_POST['time'];
$collection = @$_POST['collection'];
$file = @$_FILES['file'];
$attributes = @$_POST['attributes'];
$signature = @$_POST['signature'];

if (!isset($time) || !isset($collection) || ($file['error'] !== UPLOAD_ERR_OK) || !isset($attributes) || !isset($signature)) {
    http_response_code(400);
    exit;
}

if (preg_match('/^[a-z0-9_-]+$/', $collection) !== 1) {
    http_response_code(400);
    exit;
}

if ($signature !== hash_hmac('sha256', $time.$collection.md5_file($file['tmp_name']).md5($attributes), OM_SECRET_KEY)) {
    http_response_code(401);
    exit;
}

if (time() >= $time + 30) {
    http_response_code(401);
    exit;
}

$attributes = json_decode($attributes, true);
$attributes['access'] = array_key_exists('access', $attributes) ? $attributes['access'] : OM_DEFAULT_ACCESS;
$attributes['mime_type'] = array_key_exists('mime_type', $attributes) ? $attributes['mime_type'] : mime_content_type($file['tmp_name']);
$attributes['cache_age'] = array_key_exists('cache_age', $attributes) ? $attributes['cache_age'] : OM_DEFAULT_CACHE_AGE;
$attributes['ttl'] = array_key_exists('ttl', $attributes) ? $attributes['ttl'] : OM_DEFAULT_TTL;

$collectionPath = __DIR__.'/../storage/'.$collection;
if (!is_dir($collectionPath)) {
    if (mkdir($collectionPath) === false) {
        http_response_code(500);
        exit;
    }
}

$fileIdDict = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
$fileId = '';
for ($i = 0; $i < 32; $i++) {
    $fileId .= $fileIdDict[random_int(0, strlen($fileIdDict) - 1)];
}

$blobPath = $collectionPath.'/'.$fileId.'.blob';
if (move_uploaded_file($file['tmp_name'], $blobPath) === false) {
    http_response_code(500);
    exit;
}

$metaPath = $collectionPath.'/'.$fileId.'.meta';
if (file_put_contents($metaPath, json_encode($attributes)) === false) {
    http_response_code(500);
    exit;
}

$objectId = $collection.'/'.$fileId;

http_response_code(200);
header('Content-Type: application/json');
echo json_encode(['object_id' => $objectId]);
exit;
