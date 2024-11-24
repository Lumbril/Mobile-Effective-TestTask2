package com.example.server.exceptions;

public class ClientExistsException extends RuntimeException {
    public ClientExistsException() {
        super("Пользователь с таким именем уже есть.");
    }
}