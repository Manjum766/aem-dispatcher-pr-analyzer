package com.example.security;

public class HardcodedPassword {

    // Sonar should flag this
    private static final String PASSWORD = "admin123";

    public boolean login(String user, String password) {
        return "admin".equals(user) && PASSWORD.equals(password);
    }
}