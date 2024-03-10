<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'name' => ['required','string','min:5'],
            'lastname' => ['required','string','min:5'],
            'n_doc' => ['required','int','min:9','unique:user'],
            'number_phone' => ['required','int'],
            'email' => ['required','email:filter'],
            'password' => ['required','string','min:6','confirmed'],
            'role' => ['required','string'],

        ];
    }
}
