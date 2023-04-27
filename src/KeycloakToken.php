<?php

namespace g4t\Keycloak;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class KeycloakToken
{
    /**
     * Decode a JWT token using a public key.
     *
     * @param string|null $token The token to decode
     * @param string $publicKey The public key to use for decoding
     * @param int $leeway The number of seconds to allow for clock skew
     *
     * @return object|null The decoded token, or null if the token is invalid or missing
     */
    public static function decode(?string $token, string $publicKey, int $leeway = 0): ?object
    {
        if (!$token) {
            return null;
        }

        $publicKey = self::formatPublicKey($publicKey);

        JWT::$leeway = $leeway;

        try {
            return JWT::decode($token, new Key($publicKey, 'RS256'));
        } catch (\Throwable $exception) {
            return null;
        }
    }

    /**
     * Format a public key to be used for decoding.
     *
     * @param string $publicKey The public key to format
     *
     * @return string The formatted public key
     */
    private static function formatPublicKey(string $publicKey): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . wordwrap($publicKey, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
    }
}
