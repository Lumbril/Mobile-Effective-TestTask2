package com.example.server.utils.jwt.services;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserWithIdDetails extends UserDetails {
    Long getId();
}
