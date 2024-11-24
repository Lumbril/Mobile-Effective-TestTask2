package com.example.server.utils.jwt.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    private String privateKey;
    private String publicKey;
    private long accessTokenExpiration;
    private long refreshTokenExpiration;
}
