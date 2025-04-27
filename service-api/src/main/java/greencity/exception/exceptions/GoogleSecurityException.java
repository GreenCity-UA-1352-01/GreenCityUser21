package greencity.exception.exceptions;

/**
 * Exception that we get when user trying to sign-in with Google and something went wrong.
 */
public class GoogleSecurityException extends RuntimeException {
    /**
     * Constructor.
     */
    public GoogleSecurityException(String message) {
        super(message);
    }

    public GoogleSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
