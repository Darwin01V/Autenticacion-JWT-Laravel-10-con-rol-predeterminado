<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;


class CkeckJWT
{
    public function handle($request, Closure $next, ...$roles)
    {
        try {
            // Verifica el token JWT y obtiene el usuario autenticado actualmente
            $user = Auth::user();

            // Verifica si el usuario existe y tiene al menos un rol de los roles proporcionados
            if ($user && $this->checkRoles($user, $roles)) {
                // Agrega el rol del usuario a la solicitud
                $request->attributes->add(['role' => $user->role]);
                return $next($request);
            }

            return response()->json(['error' => 'Acceso no autorizado'], 403);
        } catch (\Exception $e) {
            Log::error('Error en el middleware: ' . $e->getMessage());
            return response()->json(['error' => 'Acceso no autorizado'], 403);
        }
    }

    protected function checkRoles($user, $roles)
    {
        // Verifica si el usuario tiene al menos uno de los roles proporcionados
        return in_array($user->role, $roles);
    }
}
