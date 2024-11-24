package com.example.server.utils.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenBody {
    private Long userId;
    private String username;
    private String tokenType;
    private String jti;
    private Date iat;
    private Date exp;
}
