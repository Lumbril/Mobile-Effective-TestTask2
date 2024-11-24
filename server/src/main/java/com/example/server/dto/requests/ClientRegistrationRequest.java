package com.example.server.dto.requests;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequest {
    @NotBlank
    @JsonProperty(value = "email", required = true)
    private String email;

    @NotBlank
    @JsonProperty(value = "password", required = true)
    private String password;

    @NotBlank
    @JsonProperty(value = "password_confirm", required = true)
    private String passwordConfirm;
}
