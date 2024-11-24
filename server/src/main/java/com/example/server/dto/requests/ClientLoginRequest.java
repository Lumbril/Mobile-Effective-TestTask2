package com.example.server.dto.requests;

import com.example.server.utils.jwt.dto.UserDataForCreateTokens;
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
public class ClientLoginRequest extends UserDataForCreateTokens {
    @NotBlank
    @JsonProperty(value = "email", required = true)
    private String username;
}