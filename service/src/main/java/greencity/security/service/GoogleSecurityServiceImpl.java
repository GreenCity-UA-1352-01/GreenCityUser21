package greencity.security.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.dto.user.UserVO;
import greencity.exception.exceptions.GoogleSecurityException;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.jwt.JwtTool;
import greencity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * Service implementation that handles Google OAuth2 authentication logic.
 * <p>
 * This service is responsible for:
 * <ul>
 *     <li>Generating the Google OAuth2 authorization URL for user redirection.</li>
 *     <li>Exchanging the authorization code for an ID token from Google.</li>
 *     <li>Verifying the ID token and signing in or registering the user.</li>
 * </ul>
 *
 * @author Roman Diakov
 * @author Volodymyr Saienko
 * @version 1.0
 */

@Service
@RequiredArgsConstructor
public class GoogleSecurityServiceImpl implements GoogleSecurityService {
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final UserService userService;
    private final JwtTool jwtTool;
    private final OwnSecurityService ownSecurityService;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    @Value("${google.oauth.client-id}")
    private String clientId;
    @Value("${google.oauth.client-secret}")
    private String clientSecret;
    @Value("${google.oauth.redirect-uri}")
    private String redirectUri;


    /**
     * Creates the Google OAuth2 authorization URL with required scopes and parameters.
     *
     * @return the authorization URL as a {@link String}
     */
    @Override
    public String createGoogleAuthUrl() {

        String scope = "openid email profile";
        String encodedScope = URLEncoder.encode(scope, StandardCharsets.UTF_8);

        return UriComponentsBuilder
                .fromHttpUrl("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", encodedScope)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("access_type", "offline")
                .queryParam("include_granted_scopes", "true")
                .queryParam("prompt", "consent")
                .build(true)
                .toUriString();
    }

    /**
     * Handles the OAuth2 callback from Google, verifies the ID token,
     * registers the user if necessary, and returns authentication tokens.
     *
     * @param code the authorization code received from Google
     * @return {@link SuccessSignInDto} containing authentication tokens and user information
     * @throws GoogleSecurityException if the ID token is invalid or exchange fails
     */
    @Transactional
    @Override
    public SuccessSignInDto handleGoogleCallback(String code) {
        try {
            String idToken = exchangeCodeForToken(code);
            GoogleIdToken googleIdToken = googleIdTokenVerifier.verify(idToken);

            if (googleIdToken == null) {
                throw new GoogleSecurityException("Invalid ID token");
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();

            if (Boolean.FALSE.equals(payload.getEmailVerified())) {
                throw new GoogleSecurityException("Google account e-mail is not verified");
            }
            String email = payload.getEmail();

            String name = (String) payload.get("name");

            UserVO user = userService.findByEmail(email);

            if (user == null) {
                var signUpDto = OwnSignUpDto.builder()
                        .name(name)
                        .email(email)
                        .isUbs(false)
                        .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                        .build();
                ownSecurityService.signUp(signUpDto, "ua");
                user = userService.findByEmail(email);
            }

            String accessToken = jwtTool.createAccessToken(user.getEmail(), user.getRole());
            String refreshToken = jwtTool.createRefreshToken(user);

            return new SuccessSignInDto(user.getId(), accessToken, refreshToken, user.getName(), false);
        } catch (Exception e) {
            throw new GoogleSecurityException("Google sign in failed: " + e.getMessage());
        }
    }

    /**
     * Exchanges the provided authorization code for an ID token by calling Google's token endpoint.
     *
     * @param code the authorization code received from Google
     * @return the ID token as a {@link String}
     * @throws GoogleSecurityException if the token exchange fails
     */
    private String exchangeCodeForToken(String code) {
        String tokenEndpoint = "https://oauth2.googleapis.com/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        var response =
                restTemplate.postForEntity(tokenEndpoint, request, Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new GoogleSecurityException("Google token endpoint returned " + response.getStatusCode());
        }

        var responseBody = response.getBody();
        if (responseBody == null || responseBody.get("id_token") == null) {
            throw new GoogleSecurityException("Failed to retrieve ID token from Google response");
        }

        return (String) responseBody.get("id_token");
    }
}
