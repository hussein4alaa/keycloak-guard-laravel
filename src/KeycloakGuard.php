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


    public function checkTokenExpiration()
    {
        if($this->decodedToken) {
            $timestampInMs = $this->decodedToken->exp;
            $date = Carbon::createFromTimestampMs($timestampInMs);
            $now = Carbon::now();
            $expiration_date = $date->format('Y-m-d h:i:s');
            if($expiration_date < $now) {
                return true;
            }
            return false;
        }
        return true;
    }


    public function user()
    {
        if($this->config['make_keycloak_token_expired']) {
            $expired = $this->checkTokenExpiration();
            if($expired) {
                return null;
            }
        }

        if($this->config['load_user_from_database']) {
            return $this->user;
        } else {
            return $this->getUserFromKeycloak();
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


    public function attempt(array $credentials)
    {
        if(!array_key_exists('url', $credentials)) {
            return response()->json(["message" => "url required"], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (!array_key_exists('realm', $credentials)) {
            return response()->json(["message" => "realm required"], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $url = $credentials['url']."/realms/".$credentials['realm']."/protocol/openid-connect/token";

        unset($credentials['url'], $credentials['realm']);

        $response = Http::asForm()->post($url, $credentials)->json();

        return $response;
    }


    public function getUserFromKeycloak() {
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

}
