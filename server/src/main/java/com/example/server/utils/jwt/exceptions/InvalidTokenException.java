package com.example.server.utils.jwt.exceptions;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException() {
        super("Incorrect token");
    }

    public InvalidTokenException(String message) {
        super(message);
    }
}
