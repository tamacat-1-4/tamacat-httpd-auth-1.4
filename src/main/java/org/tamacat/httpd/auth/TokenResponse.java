package org.tamacat.httpd.auth;

import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Key;
import com.google.api.client.util.Preconditions;

/**
 * <p>The TokenResponse for Microsoft Azure AD OAuth2/OpenID Connect.
 *  (expires_in is not digit bug)
 * 
 * <pre>
 * A.14.  "expires_in" Syntax
 *   expires-in = 1*DIGIT
 * 
 * http://tools.ietf.org/html/rfc6749#appendix-A.14
 * </pre>
 * 
 * <p>Supports expires_in syntax both Long and String.
 * <pre>
 *   ex. "expires_in":3600 or "expires_in":"3600"
 * </pre>
 * @see com.google.api.client.auth.oauth2.TokenResonse
 */
public class TokenResponse extends GenericJson {

	/** Access token issued by the authorization server. */
	@Key("access_token")
	private String accessToken;

	/**
	 * Token type (as specified in <a
	 * href="http://tools.ietf.org/html/rfc6749#section-7.1">Access Token
	 * Types</a>).
	 */
	@Key("token_type")
	private String tokenType;

	/**
	 * Lifetime in seconds of the access token (for example 3600 for an hour) or
	 * {@code null} for none.
	 */
	// @Key("expires_in")
	private Long expiresInSeconds;

	/**
	 * Refresh token which can be used to obtain new access tokens using
	 * {@link RefreshTokenRequest} or {@code null} for none.
	 */
	@Key("refresh_token")
	private String refreshToken;

	/**
	 * Scope of the access token as specified in <a
	 * href="http://tools.ietf.org/html/rfc6749#section-3.3">Access Token
	 * Scope</a> or {@code null} for none.
	 */
	@Key
	private String scope;

	/** Returns the access token issued by the authorization server. */
	public final String getAccessToken() {
		return accessToken;
	}

	/**
	 * Sets the access token issued by the authorization server.
	 *
	 * <p>
	 * Overriding is only supported for the purpose of calling the super
	 * implementation and changing the return type, but nothing else.
	 * </p>
	 */
	public TokenResponse setAccessToken(String accessToken) {
		this.accessToken = Preconditions.checkNotNull(accessToken);
		return this;
	}

	/**
	 * Returns the token type (as specified in <a
	 * href="http://tools.ietf.org/html/rfc6749#section-7.1">Access Token
	 * Types</a>).
	 */
	public final String getTokenType() {
		return tokenType;
	}

	/**
	 * Sets the token type (as specified in <a
	 * href="http://tools.ietf.org/html/rfc6749#section-7.1">Access Token
	 * Types</a>).
	 *
	 * <p>
	 * Overriding is only supported for the purpose of calling the super
	 * implementation and changing the return type, but nothing else.
	 * </p>
	 */
	public TokenResponse setTokenType(String tokenType) {
		this.tokenType = Preconditions.checkNotNull(tokenType);
		return this;
	}

	/**
	 * Returns the lifetime in seconds of the access token (for example 3600 for
	 * an hour) or {@code null} for none.
	 */
	public final Long getExpiresInSeconds() {
		return expiresInSeconds;
	}

	/**
	 * Sets the lifetime in seconds of the access token (for example 3600 for an
	 * hour) or {@code null} for none.
	 *
	 * <p>
	 * Overriding is only supported for the purpose of calling the super
	 * implementation and changing the return type, but nothing else.
	 * </p>
	 */
	public TokenResponse setExpiresInSeconds(Long expiresInSeconds) {
		this.expiresInSeconds = expiresInSeconds;
		return this;
	}

	/**
	 * Returns the refresh token which can be used to obtain new access tokens
	 * using the same authorization grant or {@code null} for none.
	 */
	public final String getRefreshToken() {
		return refreshToken;
	}

	/**
	 * Sets the refresh token which can be used to obtain new access tokens
	 * using the same authorization grant or {@code null} for none.
	 *
	 * <p>
	 * Overriding is only supported for the purpose of calling the super
	 * implementation and changing the return type, but nothing else.
	 * </p>
	 */
	public TokenResponse setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * Returns the scope of the access token or {@code null} for none.
	 */
	public final String getScope() {
		return scope;
	}

	/**
	 * Sets the scope of the access token or {@code null} for none.
	 *
	 * <p>
	 * Overriding is only supported for the purpose of calling the super
	 * implementation and changing the return type, but nothing else.
	 * </p>
	 */
	public TokenResponse setScope(String scope) {
		this.scope = scope;
		return this;
	}

	@Override
	public TokenResponse clone() {
		return (TokenResponse) super.clone();
	}

	@Override
	public TokenResponse set(String fieldName, Object value) {
		if (fieldName.equals("expires_in")) {
			if (value instanceof String) {
				try {
					expiresInSeconds = Long.parseLong((String) value);
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Value of expires_in is not a number: " + value);
				}
			} else if (value instanceof Number) {
				expiresInSeconds = Long.valueOf(((Number) value).longValue());
			} else {
				throw new IllegalArgumentException("Unknown value type for expires_in: " + value.getClass().getName());
			}
			return (TokenResponse) super.set(fieldName, expiresInSeconds);
		}
		return (TokenResponse) super.set(fieldName, value);
	}
}
