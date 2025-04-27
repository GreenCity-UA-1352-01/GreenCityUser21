package greencity.security.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.dto.user.UserVO;
import greencity.exception.exceptions.GoogleSecurityException;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.jwt.JwtTool;
import greencity.service.UserService;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GoogleSecurityServiceImplTest {

    @Mock
    private GoogleIdTokenVerifier googleIdTokenVerifier;
    @Mock
    private UserService userService;
    @Mock
    private JwtTool jwtTool;
    @Mock
    private OwnSecurityService ownSecurityService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private RestTemplate restTemplate;
    @Mock
    private GoogleIdToken googleIdToken;
    @Mock
    private GoogleIdToken.Payload payload;
    @Mock
    private ResponseEntity<Map> responseEntity;

    private GoogleSecurityService googleSecurityService;

    @BeforeEach
    void setUp() {
        googleSecurityService = new GoogleSecurityServiceImpl(
                googleIdTokenVerifier,
                userService,
                jwtTool,
                ownSecurityService,
                passwordEncoder,
                restTemplate
        );

        ReflectionTestUtils.setField(googleSecurityService, "clientId", "test-client-id");
        ReflectionTestUtils.setField(googleSecurityService, "clientSecret", "test-client-secret");
        ReflectionTestUtils.setField(googleSecurityService, "redirectUri", "http://localhost:8080/redirect");
    }

    @Test
    void createGoogleAuthUrlTest() {
        String url = googleSecurityService.createGoogleAuthUrl();

        assertTrue(url.contains("client_id=test-client-id"));
        assertTrue(url.contains("redirect_uri=http://localhost:8080/redirect"));
        assertTrue(url.contains("scope="));
        assertTrue(url.contains("response_type=code"));
    }

    @SneakyThrows
    @Test
    void handleGoogleCallbackSuccessNewUser() {
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("id_token", "test-id-token");
        when(responseEntity.getBody()).thenReturn(tokenResponse);
        when(responseEntity.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.OK);
        when(restTemplate.postForEntity(anyString(), any(), eq(Map.class)))
                .thenReturn(responseEntity);

        when(googleIdTokenVerifier.verify(anyString())).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(payload);
        when(payload.getEmail()).thenReturn("test@example.com");
        when(payload.get("name")).thenReturn("Test User");
        when(payload.getEmailVerified()).thenReturn(true);

        when(userService.findByEmail("test@example.com"))
                .thenReturn(null)
                .thenReturn(UserVO.builder()
                        .id(1L)
                        .email("test@example.com")
                        .name("Test User")
                        .build());

        when(passwordEncoder.encode(anyString())).thenReturn("encoded_password");
        when(jwtTool.createAccessToken(anyString(), any())).thenReturn("access-token");
        when(jwtTool.createRefreshToken(any(UserVO.class))).thenReturn("refresh-token");

        doAnswer(invocation -> {
            OwnSignUpDto signUpDto = invocation.getArgument(0);
            assertEquals("Test User", signUpDto.getName());
            assertEquals("test@example.com", signUpDto.getEmail());
            assertFalse(signUpDto.isUbs());
            return null;
        }).when(ownSecurityService).signUp(any(OwnSignUpDto.class), eq("ua"));

        SuccessSignInDto result = googleSecurityService.handleGoogleCallback("test-code");

        assertNotNull(result);
        assertEquals("access-token", result.getAccessToken());
        assertEquals("refresh-token", result.getRefreshToken());
        assertEquals("Test User", result.getName());

        verify(googleIdTokenVerifier).verify("test-id-token");
        verify(userService, times(2)).findByEmail("test@example.com");
        verify(ownSecurityService).signUp(any(OwnSignUpDto.class), eq("ua"));
        verify(jwtTool).createAccessToken(eq("test@example.com"), any());
        verify(jwtTool).createRefreshToken(any(UserVO.class));
    }

    @SneakyThrows
    @Test
    void handleGoogleCallbackSuccessExistingUser() {
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("id_token", "test-id-token");
        when(responseEntity.getBody()).thenReturn(tokenResponse);
        when(responseEntity.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.OK);
        when(restTemplate.postForEntity(anyString(), any(), eq(Map.class)))
                .thenReturn(responseEntity);

        when(googleIdTokenVerifier.verify(anyString())).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(payload);
        when(payload.getEmail()).thenReturn("test@example.com");
        when(payload.get("name")).thenReturn("Test User");
        when(payload.getEmailVerified()).thenReturn(true);

        UserVO existingUser = UserVO.builder()
                .email("test@example.com")
                .name("Test User")
                .build();
        when(userService.findByEmail("test@example.com")).thenReturn(existingUser);
        when(jwtTool.createAccessToken(anyString(), any())).thenReturn("access-token");
        when(jwtTool.createRefreshToken(any(UserVO.class))).thenReturn("refresh-token");

        SuccessSignInDto result = googleSecurityService.handleGoogleCallback("test-code");

        assertNotNull(result);
        assertEquals("access-token", result.getAccessToken());
        assertEquals("refresh-token", result.getRefreshToken());
        verify(ownSecurityService, never()).signUp(any(), any());
    }

    @SneakyThrows
    @Test
    void handleGoogleCallbackInvalidToken() {
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("id_token", "test-id-token");
        when(responseEntity.getBody()).thenReturn(tokenResponse);
        when(responseEntity.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.OK);
        when(restTemplate.postForEntity(anyString(), any(), eq(Map.class)))
                .thenReturn(responseEntity);

        when(googleIdTokenVerifier.verify(anyString())).thenReturn(null);

        assertThrows(GoogleSecurityException.class,
                () -> googleSecurityService.handleGoogleCallback("test-code"));
    }

    @SneakyThrows
    @Test
    void handleGoogleCallbackUnverifiedEmail() {
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("id_token", "test-id-token");
        when(responseEntity.getBody()).thenReturn(tokenResponse);
        when(responseEntity.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.OK);
        when(restTemplate.postForEntity(anyString(), any(), eq(Map.class)))
                .thenReturn(responseEntity);

        when(googleIdTokenVerifier.verify(anyString())).thenReturn(googleIdToken);
        when(googleIdToken.getPayload()).thenReturn(payload);
        when(payload.getEmailVerified()).thenReturn(false);

        assertThrows(GoogleSecurityException.class,
                () -> googleSecurityService.handleGoogleCallback("test-code"));
    }
}