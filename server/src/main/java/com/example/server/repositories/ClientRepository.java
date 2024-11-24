package com.example.server.repositories;

import com.example.server.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Long>  {
    Optional<Client> findByEmail(String email);
}
