/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import java.net.URL;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.tamacat.auth.model.LoginUser;
import org.tamacat.httpd.config.HttpProxyConfig;
import org.tamacat.httpd.config.ServiceUrl;
import org.tamacat.httpd.exception.ForbiddenException;
import org.tamacat.httpd.exception.ServiceUnavailableException;
import org.tamacat.httpd.exception.UnauthorizedException;
import org.tamacat.httpd.filter.RequestFilter;
import org.tamacat.httpd.filter.ResponseFilter;
import org.tamacat.httpd.filter.acl.FreeAccessControl;
import org.tamacat.httpd.util.HeaderUtils;
import org.tamacat.httpd.util.HtmlUtils;
import org.tamacat.httpd.util.RequestUtils;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.util.StringUtils;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * Implements of OpenID Connect authentication. (code flow)
 */
public class OpenIdConnectAuthProcessor implements RequestFilter, ResponseFilter {
	
	static Log LOG = LogFactory.getLog(OpenIdConnectAuthProcessor.class);

	protected ServiceUrl serviceUrl;
	protected FreeAccessControl freeAccessControl = new FreeAccessControl();

	protected String singleSignOnCookieName = "SSOSession";
	protected HttpTransport httpTransport = new NetHttpTransport();
	protected JsonFactory jsonFactory = new JacksonFactory();

	protected List<String> scopes = Arrays.asList("openid", "email", "profile");
	protected List<String> responseTypes = Arrays.asList("code");
	protected String callbackPath = "oauth2callback";
	protected String config = "openid-connect-config.json";
	protected Map<String, OpenIdConnectConfig> openIdConnectConfigs = new LinkedHashMap<>();

	protected String REDIRECT_LOOP_COUNT= "OpenIdConnect.REDIRECT_LOOP_COUNT";

	protected String loginPath = "/sso/login";
	protected String logoutPath = "/sso/logout";
	
	protected String registrationUri = "/app/user/register";

	protected String registerUserInfoUrl;
	protected Authentication authentication;

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}
	
	public void setLoginPath(String loginPath) {
		this.loginPath = loginPath;
	}

	public void setLogoutPath(String logoutPath) {
		this.logoutPath = logoutPath;
	}
	
	public void setRegisterUserInfoUrl(String registerUserInfoUrl) {
		this.registerUserInfoUrl = registerUserInfoUrl;
	}

	/**
	 * Set proxy configuration, access to ID provider through a HTTP Proxy.
	 * @param httpProxyConfig
	 */
	public void setHttpProxyConfig(HttpProxyConfig httpProxyConfig) {
		if (httpProxyConfig != null && httpProxyConfig.isDirect() == false) {
			HttpHost proxy = httpProxyConfig.getProxyHttpHost();
			System.setProperty("http.proxyHost", proxy.getHostName());
			System.setProperty("http.proxyPort", String.valueOf(proxy.getPort()));
			System.setProperty("http.proxyUser", httpProxyConfig.getCredentials().getUserPrincipal().getName());
			System.setProperty("http.proxyPassword", httpProxyConfig.getCredentials().getPassword());
			System.setProperty("http.nonProxyHosts", httpProxyConfig.getNonProxyHosts());

			System.setProperty("https.proxyHost", proxy.getHostName());
			System.setProperty("https.proxyPort", String.valueOf(proxy.getPort()));
			System.setProperty("https.proxyUser", httpProxyConfig.getCredentials().getUserPrincipal().getName());
			System.setProperty("https.proxyPassword", httpProxyConfig.getCredentials().getPassword());
			System.setProperty("https.nonProxyHosts", httpProxyConfig.getNonProxyHosts());
		}
	}

	public void setScope(String scope) {
		scopes = Arrays.asList(StringUtils.split(scope, ","));
	}

	public void setResponseTypes(String type) {
		responseTypes = Arrays.asList(StringUtils.split(type, ","));
	}

	public void setCallbackPath(String callbackPath) {
		this.callbackPath = callbackPath;
	}

	public void setRegistrationUri(String registrationUri) {
		this.registrationUri = registrationUri;
	}

	public void setFreeAccessExtensions(String freeAccessExtensions) {
		this.freeAccessControl.setFreeAccessExtensions(freeAccessExtensions);
	}

	public void setFreeAccessUrl(String freeAccessUrl) {
		this.freeAccessControl.setFreeAccessUrl(freeAccessUrl);
	}

	@Override
	public void init(ServiceUrl serviceUrl) {
		this.serviceUrl = serviceUrl;
		this.freeAccessControl.setPath(serviceUrl.getPath());
		//this.freeAccessControl.setFreeAccessUrl(loginPath);
		initOpenIdConfig();
	}

	protected void initOpenIdConfig() {
		OpenIdConnectConfigLoader loader = new OpenIdConnectConfigLoader();
		openIdConnectConfigs = loader.load(config);
	}
	
	protected OpenIdConnectConfig getOpenIdConnectConfig(String id) {
		return openIdConnectConfigs.get(id);
	}
	
	//Cookie: sid=example.com
	//URI: http://localhost/sso/login/example.com
	protected String getId(HttpRequest req, HttpContext context) {
		String sid = HeaderUtils.getCookieValue(req, "sid");
		if (StringUtils.isNotEmpty(sid)) {
			return sid;
		}
		String uri = req.getRequestLine().getUri();
		if (uri.startsWith("http://") || uri.startsWith("https://")) {
			String path;
			try {
				URL url = new URL(uri);
				path = url.getPath();
			} catch (Exception e) {
				path = uri;
			}
			uri = path.replace(loginPath+"/", "");
		}
		if (uri.indexOf('?')>=0) {
			uri = uri.substring(0, uri.indexOf("?"));
		}
		uri = uri.replaceFirst("oauth2callback$", "");
		uri = uri.replace(loginPath+"/", "");
		if (uri.indexOf('/')>=0) {
			return uri.substring(0, uri.indexOf("/"));
		} else {
			return uri;
		}
	}

	protected String getClientId(HttpRequest req, HttpContext context) {
		OpenIdConnectConfig config = getOpenIdConnectConfig(getId(req, context));
		if (config == null) {
			throw new UnauthorizedException();
		}
		return config.getClientId();
	}

	public String getUrlforCodeFlowAuth(HttpRequest req, HttpContext context, String redirectPath) {
		OpenIdConnectConfig config = getOpenIdConnectConfig(getId(req, context));
		if (config == null) {
			throw new UnauthorizedException();
		}
		AuthorizationCodeRequestUrl codeUrl = new AuthorizationCodeRequestUrl(
				config.getAuthorizationEndpoint(), getClientId(req, context));
		codeUrl.setScopes(scopes);
		codeUrl.setResponseTypes(responseTypes);
		codeUrl.setRedirectUri(redirectPath);
		return codeUrl.build();
	}

	@Override
	public void doFilter(HttpRequest req, HttpResponse resp, HttpContext context) {
		String uri = req.getRequestLine().getUri();
		//Free access or login URI (do not required authorization)
		if (freeAccessControl.isFreeAccess(uri) || uri.equals(loginPath)) {
			return;
		}
		
		//session check
		String session = authentication.check(req, resp, context);
		LOG.trace("ALREADY LOGIN SESSION CHECK session="+session);
		if (StringUtils.isNotEmpty(session)) {
			if (uri.startsWith(logoutPath)) {
				handleLogoutRequest(req, resp, context);
			}
			LOG.trace("session="+session);
			if (uri.startsWith(loginPath+"/")) {
				//redirect /login/xxxx -> /login
				sendRedirect(resp, context, loginPath);
			}
			return;
		}
		
		//redirect callback endpoint
		if (uri.indexOf("/"+ callbackPath) >= 0) {
			callback(req, resp, context);
			checkRedirectLoop(req, context);
			return;
		}
				
		String id = getSession(req, resp, context);
		if (StringUtils.isNotEmpty(id)) {
			if (getOpenIdConnectConfig(id) != null && uri.startsWith(loginPath+id)) {
				redirectUserRegistorationUri(req, resp, context);
				checkRedirectLoop(req, context);
			} else {
				resetRedirectLoopCount(req, context);
			}
		} else {
			checkRedirectLoop(req, context);
			redirectAuthorizationEndpoint(req, resp, context);
			//handleLoginErrorRequest(req, resp, context);
		}
	}
	
	protected String getSession(HttpRequest req, HttpResponse resp, HttpContext context) {
		try {
			String token = HeaderUtils.getCookieValue(req, singleSignOnCookieName);
			LOG.trace(token);
			String id = new String(Base64.getUrlDecoder().decode(token));
			return id;
		} catch (Exception e) {
			resp.setHeader("Set-Cookie", singleSignOnCookieName + "=; HttpOnly=true; Path=/; expires=Thu, 1-Jan-1970 00:00:00 GMT");
			return null;
		}
	}
	
	protected void handleLoginRequest(HttpRequest req, HttpResponse resp, HttpContext context, String username) {
		String uri = HtmlUtils.escapeHtmlMetaChars(authentication.getStartUrl(req));
		resp.setHeader("Location", uri);
		resp.setStatusCode(302);
		LOG.debug("Location: "+uri);
	}

	protected void handleLogoutRequest(HttpRequest req, HttpResponse resp, HttpContext context) {
		String domain = getId(req, context);
		OpenIdConnectConfig config = getOpenIdConnectConfig(domain);
		if (config != null) {
			String logoutUri = config.getEndSessionEndpoint();
			if (StringUtils.isNotEmpty(logoutUri)) {
				//redirect OP logout.
				sendRedirect(resp, context, logoutUri);
			}
			return;
		}
	}
	
	protected void checkRedirectLoop(HttpRequest req, HttpContext context) {
		Object count = context.getAttribute(REDIRECT_LOOP_COUNT);
		if (count != null && count instanceof AtomicInteger) {
			int result = ((AtomicInteger)count).addAndGet(1);
			if (result > 3) {
				throw new RedirectLoopException(req.getRequestLine().getUri());
			}
		} else {
			context.setAttribute(REDIRECT_LOOP_COUNT, new AtomicInteger(1));
		}
	}

	protected void resetRedirectLoopCount(HttpRequest req, HttpContext context) {
		context.removeAttribute(REDIRECT_LOOP_COUNT);
	}

	protected void redirectAuthorizationEndpoint(HttpRequest req, HttpResponse resp, HttpContext context) {
		String id = getId(req, context);
		LOG.trace("id="+id);
		OpenIdConnectConfig config = getOpenIdConnectConfig(id);
		if (config == null) {
			//redirect login.
			sendRedirect(resp, context, loginPath);
		} else {
			String authUrl = getUrlforCodeFlowAuth(req, context, config.getCallbackUri());
			sendRedirect(resp, context, authUrl);
		}
	}

	protected void redirectUserRegistorationUri(HttpRequest req, HttpResponse resp, HttpContext context) {
		String domain = getId(req, context);
		OpenIdConnectConfig config = getOpenIdConnectConfig(domain);
		if (config == null) {
			//redirect registrationUri.
			sendRedirect(resp, context, registrationUri);
			//throw new UnauthorizedException();
		} else {
			String uri = config.getRegistrationUri();
			sendRedirect(resp,context,uri);
		}
	}

	protected void sendRedirect(HttpResponse resp, HttpContext context, String uri) {
		LOG.debug("Redirect-> "+uri);
		resp.setHeader("Location", uri);
		resp.setStatusCode(302);
		context.setAttribute(SKIP_HANDLER_KEY, true);
		//context.setAttribute(SKIP_REQUEST_FILTER_KEY, true);
		//Keep-Alive -> Connection close.
		resp.setHeader(HTTP.CONN_DIRECTIVE, HTTP.CONN_CLOSE);
	}

	@Override
	public void afterResponse(HttpRequest req, HttpResponse resp, HttpContext context) {
	}

	protected void callback(HttpRequest req, HttpResponse resp, HttpContext context) {
		RequestUtils.setParameters(req, context, "UTF-8");
		String code = RequestUtils.getParameter(context, "code");
		String error = RequestUtils.getParameter(context, "error");
		String errorDescription = RequestUtils.getParameter(context, "error_description");
		if (StringUtils.isNotEmpty(error) && StringUtils.isNotEmpty(errorDescription)) {
			LOG.warn("Error="+error+", Description="+errorDescription.replace("\r", "").replace("\n", ","));
			if (code == null) {
				throw new ForbiddenException("Access Denied.");
			}
		}
		LOG.debug("#callback code=" + code);
		try {
			TokenResponse tr = getTokenResponse(req, context, code);
			processTokenResponse(req, resp, context, tr);
		} catch (AccessTokenExpiredException e) {
			redirectAuthorizationEndpoint(req, resp, context);
			//throw e;
		} catch (UnauthorizedException e) {
			context.setAttribute(EXCEPTION_KEY, e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new ServiceUnavailableException(e);
		}
	}

	public TokenResponse getTokenResponse(HttpRequest req, HttpContext context, String code) {
		if (StringUtils.isEmpty(code)) {
			return null;
		}
		String domain = getId(req, context);
		OpenIdConnectConfig config = getOpenIdConnectConfig(domain);
		if (config == null) {
			throw new ForbiddenException("Unkown Configuration");
		}
		AuthorizationCodeTokenRequest2 tokenUrl = new AuthorizationCodeTokenRequest2(
			httpTransport, jsonFactory, new GenericUrl(config.getTokenEndpoint()), code);
		tokenUrl.setGrantType("authorization_code");
		tokenUrl.setRedirectUri(config.getCallbackUri());
		tokenUrl.set("client_id", getClientId(req, context));
		tokenUrl.set("client_secret", config.getClientSecret());
		LOG.debug("tokenUrl=" + tokenUrl.toString());

		try {
			return tokenUrl.execute2();
		} catch (TokenResponseException e) {
			throw new AccessTokenExpiredException(e);
		} catch (Exception e) {
			throw new ServiceUnavailableException(e);
		}
	}

	protected void processTokenResponse(HttpRequest req, HttpResponse resp, HttpContext context, TokenResponse tokenResponse) {
		IdToken idToken = getIdToken(tokenResponse);
		String id = getId(req, context);
		OpenIdConnectConfig config = getOpenIdConnectConfig(id);

		String upn = null;
		if ("subject".equals(config.getUpn())) {
			upn = (String) idToken.getPayload().getSubject();
		} else {
			upn = (String) idToken.getPayload().get(config.getUpn());
		}
		String sub = idToken.getPayload().getSubject();

		LOG.debug("upn="+upn+" ,subject=" + sub);

		resp.addHeader("Set-Cookie", "sid="+id+"; HttpOnly=true; Path=/"); //domain or sid
		// if local user is not exists when redirect user register URL.
		//resp.addHeader("Set-Cookie", singleSignOnCookieName + "=" + new String(Base64.getUrlEncoder().encode(id.getBytes())) + "; HttpOnly=true; Path=/");
		if (upn != null) {
			resp.addHeader("Set-Cookie", "upn="+new String(Base64.getUrlEncoder().encode(upn.getBytes()))+"; HttpOnly=true; Path=/");
		} else {
			String email = (String)idToken.getPayload().get("email");
			if (email != null) {
				resp.addHeader("Set-Cookie", "upn="+new String(Base64.getUrlEncoder().encode(email.getBytes()))+"; HttpOnly=true; Path=/");
			}
		}
		resp.addHeader("Set-Cookie", "subject="+new String(Base64.getUrlEncoder().encode(sub.getBytes()))+"; HttpOnly=true; Path=/");
		
		LoginUser user = authentication.getUser(upn);
		context.setAttribute(Authentication.USER, user);
		authentication.activate(req, resp, context, user.getUserId(), user.getSalt());
		sendRedirect(resp, context, config.getRedirectUri());
	}
	
	public IdToken getIdToken(TokenResponse tokenResponse) {
		if (tokenResponse != null) {
			String value = (String) tokenResponse.get("id_token");
			LOG.trace("id_token=" + value);
			try {
				IdToken idToken = IdToken.parse(jsonFactory, value);
				LOG.debug("id_token=" + idToken);
				return idToken;
			} catch (Exception e) {
				throw new ServiceUnavailableException(e);
			}
		}
		return null;
	}

	protected String getPath(String path) {
		return serviceUrl.getPath() + path.replaceFirst("^/", "");
	}
}