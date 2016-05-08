package org.tamacat.httpd.auth;

import java.io.IOException;

import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;

/**
 * <p>
 * The AuthorizationCodeTokenRequest for Microsoft Azure AD OAuth2/OpenID
 * Connect. (expires_in is not digit bug) Using
 * org.tamacat.httpd.auth.TokenResponse.
 * 
 * @see com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest
 */
public class AuthorizationCodeTokenRequest2 extends AuthorizationCodeTokenRequest {

	public AuthorizationCodeTokenRequest2(
			HttpTransport transport, JsonFactory jsonFactory, GenericUrl tokenServerUrl, String grantType) {
		super(transport, jsonFactory, tokenServerUrl, grantType);
	}

	public TokenResponse execute2() throws IOException {
		return executeUnparsed().parseAs(TokenResponse.class);
	}
}
