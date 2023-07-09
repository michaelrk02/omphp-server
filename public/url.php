<?php

require '../config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    exit;
}

$time = @$_GET['time'];
$id = @$_GET['id'];
$signature = @$_GET['signature'];

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

if (!file_exists($blobPath) || !file_exists($metaPath)) {
    http_response_code(404);
    exit;
}

$attributes = @json_decode(file_get_contents($metaPath), true);
$objectUrl = '';

if (@$attributes['access'] === 'public') {
    $objectUrl = OM_SERVER_URL.'object.php?'.http_build_query(['id' => $id]);
} else if (@$attributes['access'] === 'protected') {
    $params = [];
    $params['time'] = time();
    $params['id'] = $id;
    $params['signature'] = hash_hmac('sha256', $params['time'].$params['id'], OM_SECRET_KEY);

    $objectUrl = OM_SERVER_URL.'object.php?'.http_build_query($params);
} else {
    http_response_code(500);
    exit;
}

http_response_code(200);
header('Content-Type: application/json');
echo json_encode(['object_url' => $objectUrl]);
exit;
