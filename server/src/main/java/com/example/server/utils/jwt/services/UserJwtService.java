package com.example.server.utils.jwt.services;

public interface UserJwtService {
    UserWithIdDetails getByUsername(String username);
}
