/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import java.net.HttpCookie;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.protocol.HttpContext;
import org.tamacat.auth.OneTimePassword;
import org.tamacat.auth.model.LoginUser;
import org.tamacat.auth.model.SingleSignOnSession;
import org.tamacat.auth.util.EncryptSessionUtils;
import org.tamacat.httpd.exception.ServiceUnavailableException;
import org.tamacat.httpd.util.HeaderUtils;
import org.tamacat.httpd.util.RequestUtils;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.util.EncryptionUtils;
import org.tamacat.util.StringUtils;

public abstract class AbstractAuthentication implements Authentication {

	static final Log LOG = LogFactory.getLog(AbstractAuthentication.class);

	protected String startUrl = "/service/app/portal/main";
	protected String loginPage = "/login";
	protected String logoutPage = "/logout";
	protected boolean useSingleSignOn = true;
	protected String singleSignOnSessionKey = "SSOSession";
	protected String singleSignOnProfileKey = "SSOProfile";
	protected int stretch = 3;

	protected boolean encrypted = true;
	protected boolean isHttpOnlyCookie = true;
	protected boolean isSecureCookie;
	protected String singleSignOnCookiePath = "/";
	protected String loginKey = "key";
	protected String reverseProxyUserHeader = "X-ReverseProxy-User";
	protected OneTimePassword oneTimePassword;

	@Override
	public boolean login(HttpRequest req, HttpResponse resp, HttpContext context, String username, String password) {
		if (!"POST".equalsIgnoreCase(req.getRequestLine().getMethod())) {
			return false;
		}
		if (StringUtils.isEmpty(username) || username.length() > 255) {
			return false;
		}
		//invalidateHttpSession(req, context);
		if (encrypted) {
			String _password = RequestUtils.getParameter(context, "encrypted");
			if (StringUtils.isNotEmpty(_password)) {
				password = _password;
			}
			if (StringUtils.isEmpty(password)) {
				return false;
			}
		}
		String key = RequestUtils.getParameter(context, loginKey);
		if (StringUtils.isNotEmpty(key) && checkOneTimePassword(key, req) == false) {
			LOG.trace("OneTimePassword=false : " + key);
			return false;
		}
		//LOG.debug("login username=" + username + ", password=" + password);
		LoginUser user = getUser(username);
		if (user == null || user.isEncrypted() != encrypted || StringUtils.isEmpty(user.getUserId())
				|| StringUtils.isEmpty(user.getPassword())) {
			return false;
		}
		String authPassword = user.getPassword();
		if (StringUtils.isNotEmpty(key)) {
			authPassword = getMessageDigest(user.getPassword() + key).toLowerCase();
		}
		boolean check = user.getUserId().equals(username) && authPassword.equals(password);
		if (check) {
			context.setAttribute(USER, user);
			activate(req, resp, context, username, getUserSalt(username));
		}
		return check;
	}

	public void setOneTimePassword(OneTimePassword oneTimePassword) {
		this.oneTimePassword = oneTimePassword;
	}

	public boolean checkOneTimePassword(String key, HttpRequest req) {
		return oneTimePassword != null && oneTimePassword.check(getSecretKey(), key);
	}

	public String generateOneTimePassword() {
		return oneTimePassword != null ? oneTimePassword.generate(getSecretKey()) : null;
	}

	public abstract LoginUser getUser(String username);

	protected String getUserSalt(String username) {
		return generateSessionId(username, "", 0);
	}

	@Override
	public String check(HttpRequest req, HttpResponse resp, HttpContext context) {
		String session = HeaderUtils.getCookieValue(req, singleSignOnSessionKey);
		LOG.trace("check session=" + session);
		if (StringUtils.isNotEmpty(session) && checkSessionId(req, context, session)) {
			String decrypted = decryptSession(session);
			LOG.trace("decryptSession=" + decrypted);
			if (decrypted != null) {
				SingleSignOnSession sso = SingleSignOnSession.parseSession(decrypted);
				if (sso != null) {
					String username = sso.getUsername();
					resp.setHeader(reverseProxyUserHeader, username);
					
					String profile = sso.getProfile();
					if (profile != null) {
						String json = decryptSession(profile);
						LOG.trace(json);
					}
					return username;
				}
			}
		}
		return null;
	}

	public void activate(HttpRequest req, HttpResponse resp, HttpContext context, String username, String salt) {
		long time = System.nanoTime();
		LoginUser user = (LoginUser) context.getAttribute(USER);
		if (user == null || ! username.equalsIgnoreCase(user.getUserId())) {
			throw new ServiceUnavailableException();
		}
		String sessionId = generateSessionId(username, salt, time);
		if (LOG.isTraceEnabled()) {
			LOG.trace("username="+username+", salt="+salt+", time="+time);
			LOG.trace("session="+sessionId);
		}
		String encrypted = encryptSession(username + "\t" + sessionId + "\t" + time);
		BasicClientCookie sessionCookie = new BasicClientCookie(singleSignOnSessionKey, encrypted);
		sessionCookie.setPath(singleSignOnCookiePath);
		resp.setHeader("Set-Cookie", HeaderUtils.getSetCookieValue(sessionCookie, isHttpOnlyCookie, isSecureCookie));
		
		String profile = user.toJson();
		if (profile != null) {
			BasicClientCookie profileCookie = new BasicClientCookie("SSOProfile", encryptSession(profile));
			profileCookie.setPath(singleSignOnCookiePath);
			resp.addHeader("Set-Cookie", HeaderUtils.getSetCookieValue(profileCookie, isHttpOnlyCookie, isSecureCookie));
		}
	}
	
	public String getSecretKey() {
		return EncryptSessionUtils.getSecretKey();
	}
	
	public String encryptSession(String session) {
		return EncryptSessionUtils.encryptSession(session);
	}
	
	public String decryptSession(String session) {
		return EncryptSessionUtils.decryptSession(session);
	}

	@Override
	public void logout(HttpRequest req, HttpResponse resp, HttpContext context, String username) {
		HttpCookie cookie = new HttpCookie(singleSignOnSessionKey, "");
		cookie.setPath(singleSignOnCookiePath);
		cookie.setMaxAge(0);
		resp.setHeader("Set-Cookie", cookie.toString());
	}

	protected String generateSessionId(String username, String salt, long time) {
		String value = username + ":" + time + ":" + salt;
		for (int i = 0; i < stretch; i++) {
			String md = getMessageDigest(value);
			if (md != null) {
				value = md;
			}
		}
		return value;
	}

	protected String getMessageDigest(String value) {
		return EncryptionUtils.getMessageDigest(value, "SHA-256").toLowerCase();
	}

	protected boolean checkSessionId(HttpRequest req, HttpContext context, String session) {
		String value = decryptSession(session);
		SingleSignOnSession sso = SingleSignOnSession.parseSession(value);
		if (sso != null) {
			String username = sso.getUsername();
			String salt = getUserSalt(username);
			LoginUser user = getUser(username);
			if (user != null) {
				String digest = generateSessionId(username, salt, StringUtils.parse(sso.getCreated(), 0L));
				if (LOG.isTraceEnabled()) {
					LOG.trace("user=" + username + ", salt=" + salt);
					LOG.trace("checkSessionId Session:digest=" + sso.getSessionId());
					LOG.trace("checkSessionId      DB:digest=" + digest);
				}
				boolean result = digest != null && digest.equals(sso.getSessionId());
				if (result) {
					context.setAttribute(USER, user);
				}
				return result;
			}
		}
		return false;
	}

	public String getStartUrl() {
		return startUrl;
	}

	public void setStartUrl(String startUrl) {
		this.startUrl = startUrl;
	}

	public String getLoginPage() {
		return loginPage;
	}

	public void setLoginPage(String loginPage) {
		this.loginPage = loginPage;
	}

	public String getLogoutPage() {
		return logoutPage;
	}

	public void setLogoutPage(String logoutPage) {
		this.logoutPage = logoutPage;
	}

	@Override
	public String getStartUrl(HttpRequest req) {
		return startUrl;
	}

	@Override
	public String getLoginPage(HttpRequest req) {
		return loginPage;
	}

	@Override
	public String getLogoutPage(HttpRequest req) {
		return logoutPage;
	}

	public void setStretch(int stretch) {
		this.stretch = stretch;
	}

	public void setUseSingleSignOn(boolean useSingleSignOn) {
		this.useSingleSignOn = useSingleSignOn;
	}

	public void setSingleSignOnSessionKey(String singleSignOnSessionKey) {
		this.singleSignOnSessionKey = singleSignOnSessionKey;
	}
	
	public void setSingleSignOnProfileKey(String singleSignOnProfileKey) {
		this.singleSignOnProfileKey = singleSignOnProfileKey;
	}

	public void setEncrypted(boolean encrypted) {
		this.encrypted = encrypted;
	}

	public void setHttpOnlyCookie(boolean isHttpOnlyCookie) {
		this.isHttpOnlyCookie = isHttpOnlyCookie;
	}

	public void setSecureCookie(boolean isSecureCookie) {
		this.isSecureCookie = isSecureCookie;
	}

	public void setSingleSignOnCookiePath(String singleSignOnCookiePath) {
		this.singleSignOnCookiePath = singleSignOnCookiePath;
	}

	public void setReverseProxyUserHeader(String reverseProxyUserHeader) {
		this.reverseProxyUserHeader = reverseProxyUserHeader;
	}
}
