package com.example.security;

import java.security.SecureRandom;

public class WeakRandom {

    // Use SecureRandom for all security-sensitive values (OTPs, tokens, salts)
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public int generateOtp() {
        return 100000 + SECURE_RANDOM.nextInt(900000);
    }
}
