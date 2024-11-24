package com.example.server.services.impl;

import com.example.server.dto.requests.ClientRegistrationRequest;
import com.example.server.entities.Client;
import com.example.server.entities.enums.Role;
import com.example.server.exceptions.ClientException;
import com.example.server.exceptions.ClientExistsException;
import com.example.server.exceptions.ClientPasswordException;
import com.example.server.repositories.ClientRepository;
import com.example.server.services.ClientService;
import com.example.server.utils.jwt.services.UserWithIdDetails;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {
    private final ClientRepository clientRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    @Transactional
    public Client create(ClientRegistrationRequest clientRegistrationRequest) {
        if (!clientRegistrationRequest.getPassword().equals(clientRegistrationRequest.getPasswordConfirm())) {
            throw new ClientPasswordException("Пароли не совпадают");
        }

        if (clientIsExists(clientRegistrationRequest.getEmail())) {
            throw new ClientExistsException();
        }

        Client u = Client.builder()
                .email(clientRegistrationRequest.getEmail())
                .password(bCryptPasswordEncoder.encode(clientRegistrationRequest.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        return clientRepository.save(u);
    }

    @Override
    public boolean clientIsExists(String email) {
        return clientRepository.findByEmail(email).isPresent();
    }

    @Override
    public UserWithIdDetails getByUsername(String email) {
        return clientRepository.findByEmail(email).orElseThrow(
                () -> new ClientException("Пользователь не найден")
        );
    }
}
