<?php

require '../config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    exit;
}

$id = @$_GET['id'];

if (!isset($id)) {
    http_response_code(400);
    exit;
}

$blobPath = __DIR__.'/../storage/'.$id.'.blob';
$metaPath = __DIR__.'/../storage/'.$id.'.meta';

if (!file_exists($blobPath) || !file_exists($metaPath)) {
    http_response_code(404);
    exit;
}

$attributes = @json_decode(file_get_contents($metaPath), true);

if (@$attributes['access'] === 'protected') {
    $time = @$_GET['time'];
    $signature = @$_GET['signature'];

    if (!isset($time) || !isset($signature)) {
        http_response_code(400);
        exit;
    }

    if ($signature !== hash_hmac('sha256', $time.$id, OM_SECRET_KEY)) {
        http_response_code(401);
        exit;
    }

    if (time() >= $time + $attributes['ttl']) {
        http_response_code(401);
        exit;
    }
} else {
    http_response_code(500);
    exit;
}

$fp = fopen($blobPath, 'r');
if ($fp === false) {
    http_response_code(500);
    exit;
}

http_response_code(200);

header('Content-Type: '.$attributes['mime_type']);
if ($attributes['access'] === 'public') {
    header('Cache-Control: max-age='.$attributes['cache_age']);
}

while (!feof($fp)) {
    $buffer = fread($fp, 1024);
    if ($buffer !== false) {
        echo $buffer;
    }
}

fclose($fp);

exit;
