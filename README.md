JWT AUTENTICACION CON ROL PREDETERMINADO

1. composer require php-open-source-saver/jwt-auth

2. php artisan vendor:publish --provider="PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider"

3. php artisan jwt:secret

4. Modificar el archivo auth.php en config/auth.php

    en defaults en la linea 16 remplazar
    
    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],

    en los guards agregar el codigo en la linea 38 remplazar el codigo

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
          ],
    ],



5. crear un controlador en donde se lleve la logica de autenticacion, puede ser cualquier nombre en este caso seria "AuthController" y asi mismo crearan Requests Login y Register en donde se agregaran las rules de ingreso de datos

    php artisan make:controller Auth/AuthController

    php artisan make:request LoginRequest
    php artisan make:request RegisterRequest

6. Modificar el modelo User

<?php

namespace App\Models;

use Laravel\Sanctum\HasApiTokens;
use Illuminate\Notifications\Notifiable;
//use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $guarded= [];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];

    
        /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}



7. Crear el middleware CkekJWt

php artisan make:middleware CkeckJWT 

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


8. Publicarlo en el archivo kernel.php

     */
    protected $middlewareAliases = [
        'CkeckJWT' => \App\Http\Middleware\CkeckJWT::class,
    ];


9. Implementar el CkeckJWT en routes/api.php
Route::middleware(['CheckJWT'])->group(function () {

    Route::get('auth/register', function (\Illuminate\Http\Request $request) {
        $role = $request->attributes->get('role', 'unknown');

        if ($role === 'admin') {
            return app()->call([AuthController::class, 'login']);
        } else {
            return response()->json(['message' => 'No tienes acceso a ese módulo'], 403);
        }
    });
});

