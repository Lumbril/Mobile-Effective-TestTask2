package com.example.server.services;

import com.example.server.dto.requests.ClientRegistrationRequest;
import com.example.server.entities.Client;
import com.example.server.utils.jwt.services.UserJwtService;

public interface ClientService extends UserJwtService {
    Client create(ClientRegistrationRequest clientRegistrationRequest);

    boolean clientIsExists(String email);
}
