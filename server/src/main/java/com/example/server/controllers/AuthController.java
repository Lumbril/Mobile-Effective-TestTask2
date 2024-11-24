package com.example.server.controllers;

import com.example.server.dto.requests.ClientLoginRequest;
import com.example.server.dto.requests.ClientRegistrationRequest;
import com.example.server.dto.requests.RefreshTokensRequest;
import com.example.server.dto.responses.AccessAndRefreshTokensResponse;
import com.example.server.dto.responses.ErrorResponse;
import com.example.server.exceptions.ClientExistsException;
import com.example.server.exceptions.ClientInvalidDataException;
import com.example.server.exceptions.ClientPasswordException;
import com.example.server.exceptions.ServerErrorException;
import com.example.server.services.impl.ClientServiceImpl;
import com.example.server.utils.jwt.dto.AccessAndRefreshJwt;
import com.example.server.utils.jwt.exceptions.InvalidTokenException;
import com.example.server.utils.jwt.services.impl.JwtServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Auth", description = "API for registration and generation JWT")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final ClientServiceImpl clientService;
    private final JwtServiceImpl jwtService;

    @Operation(summary = "Регистрация")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201"
            ),
            @ApiResponse(
                    responseCode = "400",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    @PostMapping("/registration")
    public ResponseEntity<?> registration(@Validated @RequestBody ClientRegistrationRequest clientRegistrationRequest) {
        clientService.create(clientRegistrationRequest);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @Operation(summary = "Получить Access JWT и Refresh JWT")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccessAndRefreshTokensResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody ClientLoginRequest userLoginRequest) {
        AccessAndRefreshJwt accessAndRefreshJwt = jwtService.createAccessAndRefreshTokens(userLoginRequest);

        return ResponseEntity.ok().body(
                AccessAndRefreshTokensResponse.builder()
                        .accessToken(accessAndRefreshJwt.getAccessToken())
                        .refreshToken(accessAndRefreshJwt.getRefreshToken())
                        .build()
        );
    }

    @Operation(summary = "Обновить токены")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccessAndRefreshTokensResponse.class)
                    )
            )
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Validated @RequestBody RefreshTokensRequest refreshRequest) {
        AccessAndRefreshJwt accessAndRefreshJwt = jwtService.refreshTokens(refreshRequest);

        return ResponseEntity.ok().body(AccessAndRefreshTokensResponse.builder()
                .accessToken(accessAndRefreshJwt.getAccessToken())
                .refreshToken(accessAndRefreshJwt.getRefreshToken())
                .build());
    }

    @ExceptionHandler(ClientExistsException.class)
    public ResponseEntity<?> handleUserExists(ClientExistsException exception) {
        return ResponseEntity.badRequest().body(
                ErrorResponse.builder()
                        .error(exception.getMessage())
                        .build()
        );
    }

    @ExceptionHandler(ClientPasswordException.class)
    public ResponseEntity<?> handleUserPasswordError(ClientPasswordException exception) {
        return ResponseEntity.badRequest().body(
                ErrorResponse.builder()
                        .error(exception.getMessage())
                        .build()
        );
    }

    @ExceptionHandler(ClientInvalidDataException.class)
    public ResponseEntity<?> handleUserInvalidData(ClientInvalidDataException exception) {
        return ResponseEntity.badRequest().body(
                ErrorResponse.builder()
                        .error(exception.getMessage())
                        .build()
        );
    }

    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<?> handleServerError(ServerErrorException exception) {
        return ResponseEntity.internalServerError().body(
                ErrorResponse.builder()
                        .error(exception.getMessage())
                        .build()
        );
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<?> handleInvalidToken(InvalidTokenException exception) {
        return ResponseEntity.badRequest().body(
                ErrorResponse.builder()
                        .error(exception.getMessage())
                        .build()
        );
    }
}
