package com.example.security;

public class CodeSmellExample {

    public void process(int value) {

        if (value == 1) {
            System.out.println("one");
        } else if (value == 2) {
            System.out.println("two");
        } else if (value == 3) {
            System.out.println("three");
        } else if (value == 4) {
            System.out.println("four");
        } else if (value == 5) {
            System.out.println("five");
        } else if (value == 6) {
            System.out.println("six");
        } else if (value == 7) {
            System.out.println("seven");
        } else {
            System.out.println("other");
        }
    }
}