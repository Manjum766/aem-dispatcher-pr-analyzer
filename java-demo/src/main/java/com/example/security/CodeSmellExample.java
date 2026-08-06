package com.example.security;

public class CodeSmellExample {

    // Replace long if-else chain with a switch expression (Java 14+)
    public void process(int value) {
        String label = switch (value) {
            case 1 -> "one";
            case 2 -> "two";
            case 3 -> "three";
            case 4 -> "four";
            case 5 -> "five";
            case 6 -> "six";
            case 7 -> "seven";
            default -> "other";
        };
        System.out.println(label);
    }
}
