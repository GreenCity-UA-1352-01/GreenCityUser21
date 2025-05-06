package greencity.security.service;

import greencity.security.dto.AccessRefreshTokensDto;
import greencity.security.dto.SuccessSignInDto;

/**
 * Provides the interface to manage Google security.
 */
public interface GoogleSecurityService {
    /**
     * Creates Google OAuth2 authorization URL.
     *
     * @return Google authorization URL
     */
    String createGoogleAuthUrl();

    /**
     * Processes Google OAuth2 callback with authorization code.
     *
     * @param code Authorization code from Google
     * @return SuccessSignInDto with tokens
     */
    SuccessSignInDto handleGoogleCallback(String code);
}
