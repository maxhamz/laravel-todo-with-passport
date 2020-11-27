<?php

namespace App\Http\Controllers\api\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Client as OClient; 


class AuthController extends Controller
{


    public function register(Request $request) {

        print_r("REGISTER USER AT AUTH CONTROLLER \n\n");

        $validator = Validator::make($request->all(), [
            'username' => 'required|string|min:6|max:16',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
            'c_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors'=>$validator->errors()], env('CD_BAD_REQUEST'));            
        }

        $creds = $request->only('username', 'email', 'password');

        $creds['password'] = bcrypt($creds['password']);

        $user = User::create($creds);


        $userJSON = json_encode($user);

        $response = json_encode([
            'status' => env('CD_REGISTER_SUCCESS'),
            'message' => env('MSG_SUCCESS'),
            'result' => $userJSON
        ]);

        return $response;
    }



    public function login(Request $request) {

        print_r("LOGIN USER AT AUTH CONTROLLER \n\n");

        $creds = $request->only('email', 'password');


        if(Auth::attempt($creds)) {
            print_r("CREDENTIALS VALID \n\n");

            $user = Auth::user();

            $token = $user->createToken('access')->accessToken;

            $response = json_encode([
                'status' => env('CD_SUCCESS'),
                'message' => env('MSG_OK'),
                'token_type' =>'Bearer',
                'access_token' => $token
            ]);

            return $response;

        } else {
            return response()->json([env('MSG_ERRORS')=>env('')], 401);
        }

    }


    public function getTokenAndRefreshToken(OClient $oClient, $creds) {
        $oClient = OClient::where('password_client', 1)->first();

    }



}
