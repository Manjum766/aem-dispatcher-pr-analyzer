package com.example.security;

import java.util.Objects;

/**
 * Demonstrates reading credentials from the environment instead of
 * hardcoding them in source code.
 */
public class HardcodedPassword {

    private final String credential;

    public HardcodedPassword() {
        this.credential = Objects.requireNonNull(
                System.getenv("APP_PASSWORD"),
                "Required environment variable 'APP_PASSWORD' is not set.");
    }

    public boolean login(String user, String inputCredential) {
        return "admin".equals(user) && credential.equals(inputCredential);
    }
}
