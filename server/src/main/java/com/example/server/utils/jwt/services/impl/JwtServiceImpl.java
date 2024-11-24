package com.example.server.utils.jwt.services.impl;

import com.example.server.utils.jwt.dto.AccessAndRefreshJwt;
import com.example.server.utils.jwt.dto.RefreshJwt;
import com.example.server.utils.jwt.dto.TokenBody;
import com.example.server.utils.jwt.dto.UserDataForCreateTokens;
import com.example.server.utils.jwt.exceptions.InvalidTokenException;
import com.example.server.utils.jwt.exceptions.KeyErrorException;
import com.example.server.utils.jwt.exceptions.UserInvalidDataException;
import com.example.server.utils.jwt.properties.JwtProperties;
import com.example.server.utils.jwt.services.JwtService;
import com.example.server.utils.jwt.services.UserJwtService;
import com.example.server.utils.jwt.services.UserWithIdDetails;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {
    private final JwtProperties jwtProperties;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserJwtService userService;

    @Override
    public AccessAndRefreshJwt createAccessAndRefreshTokens(UserDataForCreateTokens userData) {
        UserWithIdDetails user = getUserDetailsIfPasswordCorrect(userData);

        String accessToken = createAccessToken(user);
        String refreshToken = createRefreshToken(user);

        return AccessAndRefreshJwt.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public AccessAndRefreshJwt refreshTokens(RefreshJwt refreshJWT) {
        TokenBody tokenBody = getTokenBody(refreshJWT.getRefreshToken());

        if (!tokenBody.getTokenType().equals("refresh")) {
            throw new InvalidTokenException();
        }

        UserWithIdDetails client = userService.getByUsername(tokenBody.getUsername());

        String accessToken = createAccessToken(client);
        String refreshToken = createRefreshToken(client);

        return AccessAndRefreshJwt.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public TokenBody getTokenBody(String token) {
        Claims claims = getClaimsIfTokenValid(token);

        return TokenBody.builder()
                .userId(claims.get("user_id", Long.class))
                .username(claims.get("username", String.class))
                .tokenType(claims.get("token_type", String.class))
                .jti(claims.getId())
                .iat(claims.getIssuedAt())
                .exp(claims.getExpiration())
                .build();
    }

    private Claims getClaimsIfTokenValid(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException |
                 UnsupportedJwtException |
                 MalformedJwtException |
                 SignatureException |
                 IllegalArgumentException exception) {
            throw new InvalidTokenException();
        }
    }

    private UserWithIdDetails getUserDetailsIfPasswordCorrect(UserDataForCreateTokens user) {
        UserWithIdDetails userFromDb = userService.getByUsername(user.getUsername());

        if (!bCryptPasswordEncoder.matches(user.getPassword(), userFromDb.getPassword())) {
            throw new UserInvalidDataException();
        }

        return userFromDb;
    }

    private String createAccessToken(UserWithIdDetails user) {
        return buildToken(new HashMap<>(), user, "access", jwtProperties.getAccessTokenExpiration());
    }

    private String createRefreshToken(UserWithIdDetails user) {
        return buildToken(new HashMap<>(), user, "refresh", jwtProperties.getRefreshTokenExpiration());
    }

    private String buildToken(Map<String, Object> extraClaims, UserWithIdDetails userDetails, String type, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setHeaderParam("typ", "JWT")
                .claim("user_id", userDetails.getId())
                .claim("username", userDetails.getUsername())
                .claim("token_type", type)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .signWith(getPrivateKey(), SignatureAlgorithm.RS512)
                .compact();
    }

    private Key getPrivateKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte [] bytes = Base64.getDecoder().decode(jwtProperties.getPrivateKey());
            PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(bytes);

            return keyFactory.generatePrivate(keySpecPv);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyErrorException(e.getMessage());
        }
    }

    private Key getPublicKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte [] bytes = Base64.getDecoder().decode(jwtProperties.getPublicKey());
            X509EncodedKeySpec keySpecPv = new X509EncodedKeySpec(bytes);

            return keyFactory.generatePublic(keySpecPv);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyErrorException(e.getMessage());
        }
    }
}
