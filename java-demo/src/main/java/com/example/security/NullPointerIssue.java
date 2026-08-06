package com.example.security;

public class NullPointerIssue {

    // Guard against null input before dereferencing
    public int getLength(String value) {
        if (value == null) {
            return 0;
        }
        return value.length();
    }
}
