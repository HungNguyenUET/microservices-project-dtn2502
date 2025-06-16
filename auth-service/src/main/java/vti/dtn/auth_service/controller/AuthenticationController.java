package vti.dtn.auth_service.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import vti.dtn.auth_service.dto.request.LoginRequest;
import vti.dtn.auth_service.dto.request.RegisterRequest;
import vti.dtn.auth_service.dto.response.LoginResponse;
import vti.dtn.auth_service.dto.response.RegisterResponse;
import vti.dtn.auth_service.services.AuthenticationService;

@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@RequestMapping(path = "/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody @Valid RegisterRequest registerRequest) {
        RegisterResponse registerResponse = authenticationService.register(registerRequest);
        return ResponseEntity
                .status(registerResponse.getStatus())
                .body(registerResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest loginRequest) {
        LoginResponse loginResponse = authenticationService.login(loginRequest);
        return ResponseEntity
                .status(loginResponse.getStatus())
                .body(loginResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
        LoginResponse response = authenticationService.refreshToken(authHeader);
        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }
}
