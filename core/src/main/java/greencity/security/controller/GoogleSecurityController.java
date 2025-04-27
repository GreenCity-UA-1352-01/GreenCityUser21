package greencity.security.controller;

import greencity.security.dto.SuccessSignInDto;
import greencity.security.service.GoogleSecurityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/googleSecurity")
@Validated
@RequiredArgsConstructor
public class GoogleSecurityController {
    private final GoogleSecurityService googleSecurityService;

    @Operation(summary = "Get Google authorization URL")
    @GetMapping
    public ResponseEntity<?> googleGetCode() {
        String googleAuthUrl = googleSecurityService.createGoogleAuthUrl();
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(googleAuthUrl));
        return ResponseEntity.status(HttpStatus.FOUND)
                .headers(headers)
                .build();
    }

    @Operation(summary = "Process Google callback")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully authenticated with Google"),
            @ApiResponse(responseCode = "400", description = "Error during Google authentication")
    })
    @GetMapping("/callback")
    public ResponseEntity<SuccessSignInDto> googleSignIn(@RequestParam String code) {
        return ResponseEntity.ok(googleSecurityService.handleGoogleCallback(code));
    }
}
