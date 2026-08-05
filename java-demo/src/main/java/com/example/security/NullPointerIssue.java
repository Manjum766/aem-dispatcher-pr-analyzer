package com.example.security;

public class NullPointerIssue {

    public int getLength(String value) {
        // Sonar bug: possible NullPointerException
        return value.length();
    }
}