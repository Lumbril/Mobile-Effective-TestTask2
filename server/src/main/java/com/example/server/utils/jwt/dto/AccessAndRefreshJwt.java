package com.example.server.utils.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AccessAndRefreshJwt {
    private String accessToken;
    private String refreshToken;
}
