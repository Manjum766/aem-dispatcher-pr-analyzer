package com.example.security;

public class HardcodedPassword {

    // Read credential from environment — never hardcode secrets in source
    private final String password;

    public HardcodedPassword() {
        String envPassword = System.getenv("APP_PASSWORD");
        this.password = (envPassword != null && !envPassword.isEmpty())
                ? envPassword
                : throwMissingEnv("APP_PASSWORD");
    }

    public boolean login(String user, String inputPassword) {
        return "admin".equals(user) && password.equals(inputPassword);
    }

    private static String throwMissingEnv(String name) {
        throw new IllegalStateException("Required environment variable '" + name + "' is not set.");
    }
}
