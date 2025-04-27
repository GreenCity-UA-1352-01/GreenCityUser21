package greencity.security.controller;

import greencity.security.dto.SuccessSignInDto;
import greencity.security.service.GoogleSecurityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class GoogleSecurityControllerTest {
    private static final String LINK = "/googleSecurity";
    private MockMvc mockMvc;

    @InjectMocks
    private GoogleSecurityController googleSecurityController;

    @Mock
    private GoogleSecurityService googleSecurityService;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(googleSecurityController)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();
    }

    @Test
    void googleGetCodeTest() throws Exception {
        String expectedUrl = "https://accounts.google.com/o/oauth2/auth?test=true";
        when(googleSecurityService.createGoogleAuthUrl()).thenReturn(expectedUrl);

        mockMvc.perform(get(LINK))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, expectedUrl))
                .andExpect(header().exists(HttpHeaders.LOCATION));

        verify(googleSecurityService).createGoogleAuthUrl();
    }

    @Test
    void googleSignInTest() throws Exception {
        String authCode = "test_auth_code";
        SuccessSignInDto expectedResponse = SuccessSignInDto.builder()
                .accessToken("test_access_token")
                .refreshToken("test_refresh_token")
                .name("Test User")
                .build();

        when(googleSecurityService.handleGoogleCallback(anyString()))
                .thenReturn(expectedResponse);

        mockMvc.perform(get(LINK + "/callback")
                        .param("code", authCode))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(expectedResponse.getAccessToken()))
                .andExpect(jsonPath("$.refreshToken").value(expectedResponse.getRefreshToken()))
                .andExpect(jsonPath("$.name").value(expectedResponse.getName()));

        verify(googleSecurityService).handleGoogleCallback(authCode);
    }

    @Test
    void googleSignInWithoutCodeTest() throws Exception {
        mockMvc.perform(get(LINK + "/callback"))
                .andExpect(status().isBadRequest());
    }
}
