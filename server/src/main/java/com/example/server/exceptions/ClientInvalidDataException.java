package com.example.server.exceptions;

public class ClientInvalidDataException extends RuntimeException {
    public ClientInvalidDataException() {
        super("Неверные данные");
    }
}