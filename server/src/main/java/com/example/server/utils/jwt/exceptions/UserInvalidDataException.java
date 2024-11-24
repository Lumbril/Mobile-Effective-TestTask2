package com.example.server.utils.jwt.exceptions;

public class UserInvalidDataException extends RuntimeException {
    public UserInvalidDataException() {
        super("Неверные данные пользователя");
    }
}
