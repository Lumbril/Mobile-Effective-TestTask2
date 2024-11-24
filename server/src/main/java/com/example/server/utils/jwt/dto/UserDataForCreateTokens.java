package com.example.server.utils.jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDataForCreateTokens {
    @NotBlank
    @JsonProperty(value = "username", required = true)
    private String username;

    @NotBlank
    @JsonProperty(value = "password", required = true)
    private String password;
}
