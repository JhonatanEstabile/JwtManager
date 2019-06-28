<?php

require_once __DIR__ . '/../vendor/autoload.php';

use JwtManager\JwtManager;

$secret = 'DyONazNKD35e3TfpcOJGHewtjxPGkjSh';
$context = 'test';
$expire = 30; //expire token time
$renew = 10; //time left to expire token

$jwtManager = new JwtManager(
    $secret,
    $context,
    $expire,
    $renew
);

//Generate token
$tokenGenerated = $jwtManager->generate('test');
print("token: ".$tokenGenerated);

//decode the token and return the data in array
$result = $jwtManager->decodePayload($tokenGenerated);
print("<br>Decoded Token payload: ");
print_r($result);

//Verify if token is valid
$result = $jwtManager->isValid($tokenGenerated);
print("<br> Is valid: ".$result);

//Check if the token is still valid
$result = $jwtManager->isOnTime($tokenGenerated);
print("<br> Is on time: ".$result);

//Return the expire time that was set
$result = $jwtManager->getexpire();
print("<br> Token expiration time: ".$result);

//Check if is needed generate new token
$result = $jwtManager->tokenNeedToRefresh($tokenGenerated);
print("<br> need to refresh token: ".$result);
