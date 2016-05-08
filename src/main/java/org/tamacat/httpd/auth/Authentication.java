/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.tamacat.auth.model.LoginUser;

public interface Authentication {
	
	String LOGIN = "Authentication.LOGIN";
	
	String USER = "Authentication.USER";

	void activate(HttpRequest req, HttpResponse resp, HttpContext context, String username, String salt);
	LoginUser getUser(String username);

	boolean login(HttpRequest req, HttpResponse resp, HttpContext context, String user, String password);

	void logout(HttpRequest req, HttpResponse resp, HttpContext context, String username);

	String check(HttpRequest req, HttpResponse resp, HttpContext context);

	String getStartUrl(HttpRequest req);

	String getLoginPage(HttpRequest req);

	String getLogoutPage(HttpRequest req);

	String generateOneTimePassword();
	
	String encryptSession(String session);
	
	String decryptSession(String session);
}
