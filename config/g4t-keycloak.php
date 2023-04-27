<?php

return [
    'realm_public_key' => env('K_REALM_PUBLIC_KEY', null),

    'user_provider_credential' => env('K_USER_PROVIDER_CREDENTIAL', 'username'),

    'token_principal_attribute' => env('K_TOKEN_PRINCIPAL_ATTRIBUTE', 'preferred_username'),

    'leeway' => env('K_LEEWAY', 0),

    'load_user_from_database' => env('K_LOAD_USER_FROM_DATABASE', false),

    'make_keycloak_token_expired' => env('K_TOKEN_EXPIRED', false),

];
