package com.example.server.utils.jwt.exceptions;

public class KeyErrorException extends RuntimeException {
    public KeyErrorException(String message) {
        super(message);
    }
}
