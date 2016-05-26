/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.tamacat.auth.model.LoginUser;

/**
 * The authentication component interface. 
 */
public interface Authentication {
	
	/**
	 * Constant to hold the logged-in user ID string. 
	 */
	String LOGIN = "Authentication.LOGIN";
	
	/**
	 * Constant to hold the logged-in user object. 
	 * (The Object implements LoginUser interface.)
	 */
	String USER = "Authentication.USER";

	/**
	 * Activate after login.
	 * @param req
	 * @param resp
	 * @param context
	 * @param username
	 * @param salt
	 */
	void activate(HttpRequest req, HttpResponse resp, HttpContext context, String username, String salt);
	
	/**
	 * Get a LoginUser object.
	 * @param username
	 * @return LoginUser object.
	 */
	LoginUser getUser(String username);

	/**
	 * Login and activate the session.
	 * @param req
	 * @param resp
	 * @param context
	 * @param user
	 * @param password
	 * @return true: Login was authorized.
	 */
	boolean login(HttpRequest req, HttpResponse resp, HttpContext context, String user, String password);

	/**
	 * Logout and invalidate the session.
	 * @param req
	 * @param resp
	 * @param context
	 * @param username
	 */
	void logout(HttpRequest req, HttpResponse resp, HttpContext context, String username);

	/**
	 * Checking if the user already logged.
	 * @param req
	 * @param resp
	 * @param context
	 * @return true: session was active.
	 */
	String check(HttpRequest req, HttpResponse resp, HttpContext context);

	/**
	 * Get the start page URL.
	 * @param req
	 * @return Start page URL.
	 */
	String getStartUrl(HttpRequest req);

	/**
	 * Get the login page URL.
	 * @param req
	 * @return Login page URL.
	 */
	String getLoginPage(HttpRequest req);

	/**
	 * Get the logout page URL.
	 * @param req
	 * @return Logout page URL.
	 */
	String getLogoutPage(HttpRequest req);

	/**
	 * Generate a one time password.
	 * @return One time password.
	 */
	String generateOneTimePassword();
	
	/**
	 * Encrypt a session string.
	 * @param session
	 * @return Encrypted session (URL safe Base64 encoded string)
	 */
	String encryptSession(String session);
	
	/**
	 * Decrypt a session string.
	 * @param session URL safe Base64 encoded string
	 * @return Decrypted session
	 */
	String decryptSession(String session);
}
