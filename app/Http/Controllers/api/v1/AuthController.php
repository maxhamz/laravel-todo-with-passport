<?php

namespace App\Http\Controllers\api\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use GuzzleHttp\Client;
use Laravel\Passport\Client as OClient; 

class AuthController extends Controller
{

    public $successStatus = 200;
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


    /*
        ATTENTION: PLEASE SERVE IN TWO PORTS TO BE ABLE TO USE HTTP GUZZLE  
    */
    public function login(Request $request) {

        print_r("LOGIN USER AT AUTH CONTROLLER \n\n");

        $creds = $request->only('email', 'password');


        if(Auth::attempt($creds)) {
            print_r("CREDENTIALS VALID \n\n");

            $user = Auth::user();

            $oClient = OClient::where('password_client', 1)->first();

            $http = new Client;
            $response = $http->request('POST', env('URL_AUTH_TOKEN'), [
                'form_params' => [
                    'grant_type' => 'password',
                    'client_id' => $oClient->id,
                    'client_secret' => $oClient->secret,
                    'username' => $user['email'], # I KNOW THIS IS WEIRD, BUT IT;S TRUE!
                    'password' => $creds['password'], # MUST USE UNHASHED
                    'scope' => '*',
                ],
            ]);

            $result = json_decode((string) $response->getBody(), true);
            return response()->json($result, $this->successStatus);


        } else {
            return response()->json([env('MSG_ERRORS')=>env('')], 401);
        }

    }


    public function logout(Request $request) {
        print_r("LOGGING OUT \n\n");
        $request->user()->token()->revoke();
        return response()->json([
            'status' => $this->successStatus,
            'message' => 'Successfully logged out'
        ]);
    }


    public function userProfile(Request $request) {
        print_r("GET CURRENT USER PROFILE \n\n");

        return response()->json([
            'status' => $this->successStatus,
            'message' => 'SUCCESS',
            'user' => $request->user()
        ]);
    }


}
