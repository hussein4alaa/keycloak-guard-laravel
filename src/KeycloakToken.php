<?php

namespace g4t\Keycloak;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class KeycloakToken
{
    public static function decode($token = null, $publicKey, $leeway = 0)
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);
        return $token ? JWT::decode($token, new Key($publicKey, 'RS256')) : null;
    }

    private static function buildPublicKey(string $key)
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }

}
