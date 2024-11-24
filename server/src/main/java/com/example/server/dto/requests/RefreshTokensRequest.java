package com.example.server.dto.requests;

import com.example.server.utils.jwt.dto.RefreshJwt;
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
public class RefreshTokensRequest implements RefreshJwt {
    @NotBlank
    @JsonProperty(value = "refresh_token", required = true)
    private String refreshToken;
}
