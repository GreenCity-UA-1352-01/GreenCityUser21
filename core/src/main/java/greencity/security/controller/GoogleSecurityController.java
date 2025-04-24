package greencity.security.controller;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.dto.user.UserVO;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.jwt.JwtTool;
import greencity.security.service.OwnSecurityService;
import greencity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/googleSecurity")
@Validated
@RequiredArgsConstructor
public class GoogleSecurityController {

    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final UserService userService;
    private final JwtTool jwtTool;
    private final OwnSecurityService ownSecurityService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping
    public ResponseEntity<?> googleGetCode() {
        String googleAuthUrl = String.format("https://accounts.google.com/o/oauth2/v2/auth" +
                        "?client_id=%s" +
                        "&response_type=code" +
                        "&scope=openid%%20email%%20profile" +
                        "&redirect_uri=%s" +
                        "&access_type=offline" +
                        "&include_granted_scopes=true" +
                        "&prompt=consent",
                "",
                "");

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(googleAuthUrl));

        return ResponseEntity.status(HttpStatus.FOUND)
                .headers(headers)
                .build();
    }

    @GetMapping("/callback")
    public ResponseEntity<?> googleSignIn(@RequestParam String code) {
        try {

            System.out.println("Success!" + code);
            RestTemplate restTemplate = new RestTemplate();
            String tokenEndpoint = "https://oauth2.googleapis.com/token";

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", "");
            params.add("client_secret", "");
            params.add("redirect_uri", "");
            params.add("grant_type", "authorization_code");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenEndpoint, request, Map.class);

            GoogleIdToken googleIdToken = googleIdTokenVerifier.verify((String) tokenResponse.getBody().get("id_token"));

            if (googleIdToken != null) {
                GoogleIdToken.Payload payload = googleIdToken.getPayload();
                System.out.println(payload.toString());
                String email = payload.getEmail();
                String name = (String) payload.get("name");
                String pictureUrl = (String) payload.get("picture");

                UserVO user = userService.findByEmail(email);


                if (user == null) {
                    var ownSignInDto = OwnSignUpDto
                            .builder()
                            .name(name)
                            .email(email)
                            .isUbs(false)
                            .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                            .build();
                    ownSecurityService.signUp(ownSignInDto, "ua");
                }


                UserVO savedUser = userService.findByEmail(email);

                String accessToken = jwtTool.createAccessToken(savedUser.getEmail(), savedUser.getRole());
                String refreshToken = jwtTool.createRefreshToken(savedUser);

                return ResponseEntity.ok(new SuccessSignInDto(savedUser.getId(), accessToken, refreshToken, savedUser.getName(), false));
            } else {
                System.out.println("Invalid ID token");
            }


            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }
}
