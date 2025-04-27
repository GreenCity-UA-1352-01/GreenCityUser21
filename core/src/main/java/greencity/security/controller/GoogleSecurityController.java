package greencity.security.controller;

import greencity.security.dto.SuccessSignInDto;
import greencity.security.service.GoogleSecurityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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

/**
 * Controller responsible for handling Google OAuth2 authentication flow.
 * <p>
 * Provides endpoints for:
 * <ul>
 *     <li>Generating Google authorization URL and redirecting users to it.</li>
 *     <li>Handling Google's OAuth2 callback and exchanging authorization code for a user token.</li>
 * </ul>
 * @author Roman Diakov
 * @author Volodymyr Saienko
 * @version 1.0
 */

@RestController
@RequestMapping("/googleSecurity")
@Validated
@RequiredArgsConstructor
@Tag(name = "Google Security Controller", description = "Handles Google OAuth2 authorization and sign-in callbacks")
public class GoogleSecurityController {
    private final GoogleSecurityService googleSecurityService;

    /**
     * Redirects the user to the Google OAuth2 authorization URL for authentication.
     *
     * @return 302 FOUND response with Location header pointing to Google OAuth2 page.
     */

    @Operation(
            summary = "Get Google authorization URL",
            description = "Generates a Google OAuth2 authorization URL and redirects the user to it for authentication."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirection to Google's OAuth2 login page")
    })
    @GetMapping
    public ResponseEntity<?> googleGetCode() {
        String googleAuthUrl = googleSecurityService.createGoogleAuthUrl();
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(googleAuthUrl));
        return ResponseEntity.status(HttpStatus.FOUND)
                .headers(headers)
                .build();
    }

    /**
     * Handles the OAuth2 callback from Google by exchanging the authorization code for a user token.
     *
     * @param code The authorization code returned by Google after user consent.
     * @return {@link SuccessSignInDto} containing authentication information.
     */
    @Operation(
            summary = "Process Google OAuth2 callback",
            description = "Handles the Google OAuth2 callback by exchanging the authorization code for a user authentication token."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully authenticated with Google and returned user token"),
            @ApiResponse(responseCode = "400", description = "Invalid authorization code or authentication error")
    })
    @GetMapping("/callback")
    public ResponseEntity<SuccessSignInDto> googleSignIn(@RequestParam String code) {
        return ResponseEntity.ok(googleSecurityService.handleGoogleCallback(code));
    }
}
