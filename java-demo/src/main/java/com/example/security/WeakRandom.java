package com.example.security;

import java.util.Random;

public class WeakRandom {

    public int generateOtp() {
        // Sonar should suggest SecureRandom
        Random random = new Random();
        return 100000 + random.nextInt(900000);
    }
}