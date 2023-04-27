<?php

namespace g4t\Keycloak;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use App\Auth\CustomUserProvider;
use Carbon\Carbon;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Arr;

class KeycloakGuard implements Guard
{
    use GuardHelpers;

    protected $provider;

    private $decodedToken;

    private $config;

    public function __construct(UserProvider $provider)
    {
        $this->config = config('g4t-keycloak');
        $this->provider = $provider;
        $this->decodedToken = null;
        $this->user = null;
        $this->authenticate();
    }

    /**
    *Authenticates the user by decoding the bearer token and validating it against the user provider credential.
    *@return string|null Returns an error message if authentication fails, otherwise returns null.
    */
    private function authenticate()
    {
        try {
            $token = request()->bearerToken();
            $this->decodedToken = KeycloakToken::decode(
                $token,
                $this->config['realm_public_key'],
                $this->config['leeway']
            );
            $this->validate([
                $this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']}
            ]);
        } catch (\Exception $e) {
            return $e->getMessage();
        }

    }


    public function check()
    {
        return !is_null($this->user());
    }


    public function guest()
    {
        return is_null($this->user());
    }


    /**
    * Checks if the decoded JWT token has expired.
    *
    * @return bool Returns true if the token has expired or if there is no decoded token available, false otherwise.
    */
    public function checkTokenExpiration()
    {
        if (!$this->decodedToken) {
            return true;
        }

        $expirationDate = Carbon::createFromTimestampMs($this->decodedToken->exp);

        return $expirationDate->isPast();
    }


    /**
    * Get the authenticated user or return null if the user is not authenticated or the token is expired.
    * @return \Illuminate\Contracts\Auth\Authenticatable|null
    */
    public function user()
    {
        if ($this->config['make_keycloak_token_expired'] && $this->checkTokenExpiration()) {
            return null;
        }

        return $this->config['load_user_from_database'] ? $this->user : $this->getUserFromKeycloak();
    }


    /**
    * Validates the user credentials and sets the authenticated user.
    *
    * @param array $credentials The user credentials to validate.
    *
    * @return bool Returns true if the user credentials are valid and the user is authenticated, or false otherwise.
    */
    public function id()
    {
        $user = $this->user();
        return $user ? $user->getAuthIdentifier() : null;
    }


    /**
    * Validate a user's credentials and attempt to set the authenticated user.
    *
    * @param  array  $credentials  The credentials to use for the validation.
    *
    * @return bool  Returns true if the validation succeeds and the user is set, false otherwise.
    */
    public function validate($credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($user) {
            $this->setUser($user);
            return true;
        }
        return false;
    }

    /**
    * Set the authenticated user.
    *
    * @param Authenticatable $user The authenticated user.
    *
    * @return void
    */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }


    /**
    * Attempt to authenticate the user with Keycloak using the provided credentials.
    *
    * @param  array  $credentials The credentials required to authenticate the user.
    *                             The 'url' and 'realm' keys are mandatory, other keys will be used as form parameters.
    * @return mixed               The response from Keycloak containing the access token or an error message if the credentials are invalid.
    */
    public function attempt(array $credentials)
    {
        $requiredKeys = ['url', 'realm'];
        foreach ($requiredKeys as $key) {
            if (!array_key_exists($key, $credentials)) {
                return response()->json(["message" => "{$key} required"], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }

        $url = $credentials['url'] . "/realms/" . $credentials['realm'] . "/protocol/openid-connect/token";
        $credentialsWithoutKeys = Arr::except($credentials, $requiredKeys);

        $response = Http::asForm()->post($url, $credentialsWithoutKeys)->json();

        return $response;
    }


    /**
    * Returns the user object extracted from the decoded Keycloak token.
    * If no token has been decoded, returns null.
    * The user object contains the following properties:
    * - id: the unique identifier of the user
    * - name: the full name of the user
    * - username: the preferred username of the user
    * - given_name: the given name (first name) of the user
    *
    * @return object|null The user object or null if no token has been decoded
    */
    public function getUserFromKeycloak()
    {
        if (!$this->decodedToken) {
            return null;
        }

        return (object) [
            'id' => $this->decodedToken->sub,
            'name' => $this->decodedToken->name,
            'username' => $this->decodedToken->preferred_username,
            'given_name' => $this->decodedToken->given_name,
        ];
    }



}
