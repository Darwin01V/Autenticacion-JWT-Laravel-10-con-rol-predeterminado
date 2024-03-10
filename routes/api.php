<?php

use App\Http\Controllers\Auth\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::post('auth/login', [AuthController::class, 'login']);

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

