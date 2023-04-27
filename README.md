# Keycloak Guard Laravel Package
The keycloak-guard-laravel package provides an integration between the Keycloak authentication server and a Laravel application. It allows you to use Keycloak as the authentication provider for your Laravel application.

Installation
You can install the package using Composer:


```sh
composer require g4t/keycloak
```

# Configuration
To configure the package, you need to add your Keycloak server details to your Laravel .env file:
```sh
K_REALM_PUBLIC_KEY=
K_LOAD_USER_FROM_DATABASE=true # get user data from database or keycloak
K_USER_PROVIDER_CREDENTIAL=username # This setting specifies the unique column name in your user provider table that will be used to retrieve the user's credentials for authentication.
K_TOKEN_PRINCIPAL_ATTRIBUTE=preferred_username # This setting specifies the key name for the attribute in the Keycloak token that will be used to check against the unique column specified in K_USER_PROVIDER_CREDENTIAL. The attribute should contain the user's unique identifier, such as a username or email address.
```

You also need to configure your Laravel application to use the keycloak guard. To do this, add the following to your `config/auth.php` file:

```sh
'guards' => [
    // Other guards...
    
    'keycloak' => [
        'driver' => 'keycloak',
        'provider' => 'users',
    ],
],

'providers' => [
    // Other providers...
    
    'users' => [
        'driver' => 'keycloak',
    ],
],
```

# Usage
Once the package is installed and configured, you can use the keycloak guard to authenticate users in your Laravel application. To authenticate a user, you can use the Auth::guard('keycloak')->attempt($credentials) method, where $credentials is an array of user credentials.

For example:
```sh
return auth('keycloak')->attempt([
      'url' => 'http://localhost:8080',
      'realm' => 'realm-name',
      'username' => 'username',
      'password' => 1234,
      'client_id' => 'client_id',
      'client_secret' => 'client_secret',
      'grant_type' => 'password',
]);
```

You can also use the auth('keycloak')->check() method to check if the user is authenticated:
```sh
if (auth('keycloak')->check()) {
    // User is authenticated
} else {
    // User is not authenticated
}
```
