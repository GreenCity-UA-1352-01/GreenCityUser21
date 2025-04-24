package greencity.security.controller;

import greencity.config.SecurityConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/googleSecurity")
@Validated
@RequiredArgsConstructor
public class GoogleSecurityController {

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
        return ResponseEntity.ok(Map.of("googleAuthUrl", googleAuthUrl));
    }

    @GetMapping ("/callback")
    public ResponseEntity<?>googleSignIn(@RequestParam String code) {
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

            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }
}
