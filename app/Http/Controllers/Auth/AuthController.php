<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{

    function login(LoginRequest $request)
    {
        try {
            $credentials = $request->validated();
            $token = auth()->attempt($credentials);
        } catch (\Exception $e) {
            // Captura excepciones generales y devuélvelas como errores
            return response()->json([
                'status' => 'failed',
                'message' => 'Error al iniciar sesión',
                'error' => $e->getMessage(),
            ], 500);
        }

        if ($token) {
            return $this->token($token, auth()->user());
        } else {
            return response()->json([
                'status' => 'failed',
                'message' => 'Credenciales no válidas',
            ], 401);
        }
    }
    

    public function register(RegisterRequest $request)
    {   
        try {
            $data = $request->validated();
            $data['password'] = Hash::make($data['password']);

            $user = User::create($data);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'failed',
                'message' => 'Error al registrar el usuario',
                'error' => $e->getMessage(),
            ], 500);
        }

        if ($user) {
            $token = auth()->login($user);
            return $this->token($token, $user);
        } else {
            return response()->json([
                'status' => 'failed',
                'message' => 'Error al crear el usuario',
            ], 500);
        }
    }

    public function token($token, $user){
        return response()->json([
            'status' => 'success',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
            ],
            'access_token' => $token,
            'type' => 'bearer'
        ]);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

}
