package com.example.server.exceptions;

public class ClientPasswordException extends RuntimeException {
    public ClientPasswordException(String message) {
        super(message);
    }
}
