<?php

namespace g4t\Keycloak;

use App\Models\Token;
use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Carbon\Carbon;
use Illuminate\Support\Facades\Http;

class KeycloakAuthProvider implements UserProvider
{

    public $config;

    public function __construct($config)
    {
        $this->config = $config;
    }

    public function retrieveById($identifier)
    {
        return User::findOrFail($identifier);
    }

    public function retrieveByToken($identifier, $token)
    {
        // Retrieve a user by their unique identifier and "remember me" token.
    }

    public function updateRememberToken(Authenticatable $user, $token)
    {
        // Update the "remember me" token for the given user in storage.
    }

    public function retrieveByCredentials(array $credentials)
    {
        $now = Carbon::now();
        $token = $credentials['api_token'];
        $check_token = Token::where('token', $token)->first();
        if ($check_token && $check_token->expired_at < $now) {
            return $this->updateOrCreateToken($token);
        } else if ($check_token && $check_token->expired_at >= $now) {
            return $check_token->user;
        } else {
            return $this->updateOrCreateToken($token);
        }
        return response()->json(["message" => "unauthorized"], 401);
    }

    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return $credentials;
        // Validate a user against the given credentials.
    }


    public function updateOrCreateToken($token)
    {
        $albox_url = env('ALBOX_URL');
        $user = json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', explode('.', $token)[1]))));
        $response = Http::withHeaders(['Authorization' => $token])->get("$albox_url/api/v4/auth/profile");
        if ($response->successful()) {
            $response = (object)$response->json();
            $albox_tll = env('ALBOX_TTL');
            User::updateOrCreate([
                'id' => $user->id
            ], [
                'id' => $user->id,
                'name' => $response->name,
                'username' => $response->username,
                'email' => $response->email,
                'role' => $user->role,
                'profile_picture' => $response->profile_picture
            ]);
            $token_info = Token::updateOrCreate([
                'token' => $token,
            ], [
                'token' => $token,
                'user_id' => $user->id,
                'expired_at' => Carbon::now()->addSeconds($albox_tll),
                'user_agent' => request()->header('User-Agent'),
                'ip_address' => request()->ip()
            ]);
            return $token_info->user;
        }
    }
}
