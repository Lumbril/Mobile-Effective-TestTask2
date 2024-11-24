package com.example.server.utils.jwt.services;

import com.example.server.utils.jwt.dto.AccessAndRefreshJwt;
import com.example.server.utils.jwt.dto.RefreshJwt;
import com.example.server.utils.jwt.dto.TokenBody;
import com.example.server.utils.jwt.dto.UserDataForCreateTokens;

public interface JwtService {
    AccessAndRefreshJwt createAccessAndRefreshTokens(UserDataForCreateTokens userData);
    AccessAndRefreshJwt refreshTokens(RefreshJwt refreshJWT);
    TokenBody getTokenBody(String token);
}
