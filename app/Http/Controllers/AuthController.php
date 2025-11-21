<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'phone' => 'required'
        ]);

        $user = User::where('phone', $request->phone)->first();

        if (!$user) {
            return response()->json([
                'status' => 'False',
                'message' => 'Invalid credentials'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        $user->update([
            'authToken' => $token,
            'is_logged_out' => '0',
        ]);

        return response()->json([
            'status' => 'True',
            'message' => 'Login successfully',
            'user' => $user,
        ], 200);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'phone' => 'required',
            'age' => 'required',
            'gender' => 'required',
        ]);


        $phone = User::where('phone', $request->phone)->first();

        if ($phone) {
            return response()->json([
                'status' => 'False',
                'message' => 'Phone number already exists, please use another number'
            ], 401);
        }

        $otp = rand(1000, 9000);

        $user = User::create([
            'name' => $request->name,
            'phone' => $request->phone,
            'age' => $request->age,
            'gender' => $request->gender,
            'otp' => $otp,
            'is_logged_out' => false,
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        $user->auth_token = $token;
        $user->save();

        return response()->json([
            'status' => true,
            'message' => 'User created successfully',
            'user' => $user,
            'token' => $token
        ], 200);
    }


    public function verifyOtp(Request $request)
    {
        $request->validate([
            'phone' => 'required',
            'otp' => 'required',
        ]);

        $user = User::where('phone', $request->phone)->first();

        if (!$user) {
            return response()->json([
                'status' => 'False',
                'message' => 'User not found'
            ], 401);
        }

        if ($user->otp == $request->otp) {
            $user->is_verified = true;
            $user->save();

            return response()->json([
                'status' => 'True',
                'message' => 'Verify OTP successfully!!'
            ], 200);
        }


        return response()->json([
            'status' => 'False',
            'message' => 'Invalid OTP.'
        ], 200);
    }

    

    public function resendOtp(Request $request)
    {

        $request->validate([
            'phone' => 'required'
        ]);

        $otp = rand(1000, 9999);

        User::where('phone', $request->phone)->update([
            'otp' => $otp
        ]);

        return response()->json([
            'status' => true,
            'message' => 'OTP resent successfully',
        ]);
    }
}
