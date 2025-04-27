package greencity.security.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.constant.ErrorMessage;
import greencity.dto.user.UserVO;
import greencity.exception.exceptions.BadRefreshTokenException;
import greencity.exception.exceptions.GoogleSecurityException;
import greencity.security.dto.AccessRefreshTokensDto;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.jwt.JwtTool;
import greencity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.UUID;

@Service
public class GoogleSecurityServiceImpl implements GoogleSecurityService {
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final UserService userService;
    private final JwtTool jwtTool;
    private final OwnSecurityService ownSecurityService;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    private String clientId;
    private String clientSecret;
    private String redirectUri;

    /**
     * Constructor.
     */
    @Autowired
    public GoogleSecurityServiceImpl(GoogleIdTokenVerifier googleIdTokenVerifier,
                                     UserService userService,
                                     JwtTool jwtTool,
                                     OwnSecurityService ownSecurityService,
                                     PasswordEncoder passwordEncoder,
                                     RestTemplate restTemplate) {
        this.googleIdTokenVerifier = googleIdTokenVerifier;
        this.userService = userService;
        this.jwtTool = jwtTool;
        this.ownSecurityService = ownSecurityService;
        this.passwordEncoder = passwordEncoder;
        this.restTemplate = restTemplate;
    }
    /**
     * Creates Google OAuth2 authorization URL.
     *
     * @return Google authorization URL
     */
    @Override
    public String createGoogleAuthUrl() {
        return String.format("https://accounts.google.com/o/oauth2/v2/auth" +
                        "?client_id=%s" +
                        "&response_type=code" +
                        "&scope=openid%%20email%%20profile" +
                        "&redirect_uri=%s" +
                        "&access_type=offline" +
                        "&include_granted_scopes=true" +
                        "&prompt=consent",
                clientId,
                redirectUri);
    }

    /**
     * Processes Google OAuth2 callback with authorization code.
     *
     * @param code Authorization code from Google
     * @return SuccessSignInDto with tokens
     */
    @Transactional
    @Override
    public SuccessSignInDto handleGoogleCallback(String code) {
        try {
            String idToken = exchangeCodeForToken(code);
            GoogleIdToken googleIdToken = googleIdTokenVerifier.verify(idToken);

            if (googleIdToken != null) {
                GoogleIdToken.Payload payload = googleIdToken.getPayload();
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
            }
            throw new GoogleSecurityException("Invalid ID token");
        } catch (Exception e) {
            throw new GoogleSecurityException("Google sign in failed: " + e.getMessage());
        }
    }

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
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenEndpoint, request, Map.class);

        return (String) response.getBody().get("id_token");
    }
}
