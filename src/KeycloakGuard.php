<?php

namespace g4t\Keycloak;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use App\Auth\CustomUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

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

    private function authenticate()
    {
        try {
            $token = request()->bearerToken();
            $this->decodedToken = KeycloakToken::decode($token, $this->config['realm_public_key'], $this->config['leeway']);
            $this->validate([$this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']}]);
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

    public function user()
    {
        if (is_null($this->user)) {
            return null;
        }
        if($this->config['load_user_from_database']) {
            return $this->user;
        }

        if (!is_null($this->decodedToken)) {
            return (object) [
                'id' => $this->decodedToken->sub,
                'name' => $this->decodedToken->name,
                'username' => $this->decodedToken->preferred_username,
                'given_name' => $this->decodedToken->given_name,
            ];
        }

        return null;
    }

    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }

        return null;
    }

    public function validate($credentials = [])
    {
        $class = $this->provider->getModel();
        $user = new $class();
        $user = $user::where($credentials)->first();
        $this->setUser($user);
        return true;
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }
}
