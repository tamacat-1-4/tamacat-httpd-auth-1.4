/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import java.util.Properties;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.velocity.VelocityContext;
import org.tamacat.httpd.config.ServiceUrl;
import org.tamacat.httpd.exception.HttpException;
import org.tamacat.httpd.exception.ServiceUnavailableException;
import org.tamacat.httpd.exception.UnauthorizedException;
import org.tamacat.httpd.filter.RequestFilter;
import org.tamacat.httpd.filter.ResponseFilter;
import org.tamacat.httpd.filter.acl.FreeAccessControl;
import org.tamacat.httpd.handler.page.VelocityPage;
import org.tamacat.httpd.util.HtmlUtils;
import org.tamacat.httpd.util.RequestUtils;
import org.tamacat.httpd.util.ServerUtils;
import org.tamacat.log.DiagnosticContext;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.util.PropertyUtils;
import org.tamacat.util.StringUtils;

/**
 * Implements of HTML Form based authentication.
 */
public class FormAuthenticationProcessor implements RequestFilter, ResponseFilter {

	static Log LOG = LogFactory.getLog(FormAuthenticationProcessor.class);
	static final DiagnosticContext DC = LogFactory.getDiagnosticContext(LOG);
	static final String DEFAULT_CONTENT_TYPE = "text/html; charset=UTF-8";

	protected String docsRoot = "htdocs/login";
	protected Authentication authentication;
	protected String loginUsernameKey = "j_username";
	protected String loginPasswordKey = "j_password";
	protected String loginPath = "/login.html";

	protected FreeAccessControl freeAccess = new FreeAccessControl();

	protected ServiceUrl serviceUrl;

	public void setDocsRoot(String docsRoot) {
		this.docsRoot = ServerUtils.getServerDocsRoot(docsRoot);
	}
	
	/**
	 * The extension skipping by the certification in comma seperated values.
	 * @param extension (CSV)
	 */
	public void setFreeAccessExtensions(String extension) {
		freeAccess.setFreeAccessExtensions(extension);
	}

	public void setFreeAccessUrl(String freeAccessUrl) {
		freeAccess.setFreeAccessUrl(freeAccessUrl);
	}

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}

	@Override
	public void init(ServiceUrl serviceUrl) {
		this.serviceUrl = serviceUrl;
		freeAccess.setPath(serviceUrl.getPath());
	}

	@Override
	public void doFilter(HttpRequest req, HttpResponse resp, HttpContext context) {
		if (authentication != null) {
			String path = req.getRequestLine().getUri();
			if (freeAccess.isFreeAccess(path)) {
				return;
			}
			try {
				// FORM LOGIN USERNAME AND PASSWORD CHECK.
				if (path.endsWith(loginPath)) {
					String username = RequestUtils.getParameter(context, loginUsernameKey);
					String password = RequestUtils.getParameter(context, loginPasswordKey);
					if ("POST".equals(req.getRequestLine().getMethod())) {
						if (authentication.login(req, resp, context, username, password)) {
							handleLoginRequest(req, resp, context, username);
							return;
						} else {
							context.setAttribute("login_error", true);
							handleLoginErrorRequest(req, resp, context);
							return;
						}
					} else {
						String checkedUsername = authentication.check(req, resp, context);
						if (StringUtils.isNotEmpty(checkedUsername)) {
							handleLoginRequest(req, resp, context, checkedUsername);
							return;
						}
					}
				}
				// ALREADY LOGIN SESSION CHECK.
				String username = authentication.check(req, resp, context);
				if (StringUtils.isNotEmpty(username)) {
					if (req.getRequestLine().getUri().endsWith("/logout.html")) {
						handleLogoutRequest(req, resp, context, username);
						return;
					}
				} else {
					handleLoginErrorRequest(req, resp, context);
					return;
				}
			} catch (HttpException e) {
				throw e;
			} catch (Exception e) {
				throw new ServiceUnavailableException(e);
			}
		}
	}

	public void afterResponse(HttpRequest req, HttpResponse resp, HttpContext context) {
		String path = req.getRequestLine().getUri();
		if (path.endsWith(loginPath)) {
			return;
		}
		if (isException(resp, context)) {
			sendRedirect(req, resp, "/login.html");
		}
	}

	protected boolean isException(HttpResponse resp, HttpContext context) {
		Exception ex = (Exception) context.getAttribute(EXCEPTION_KEY);
		return ex != null || 401 == resp.getStatusLine().getStatusCode();
	}

	protected void handleLoginRequest(HttpRequest req, HttpResponse resp, HttpContext context, String username) {
		String uri = HtmlUtils.escapeHtmlMetaChars(authentication.getStartUrl(req));
		resp.setHeader("Location", uri);
		resp.setStatusCode(302);
		LOG.debug("Location: "+uri);
	}

	protected void handleLoginErrorRequest(HttpRequest req, HttpResponse resp, HttpContext context) {
		sessionInvalidate(req);
		context.setAttribute("key", authentication.generateOneTimePassword());
		LOG.debug("auth check false");
		new LoginDispatcher(authentication.getLoginPage(req)).dispatcher(req, resp, context);
		context.setAttribute(EXCEPTION_KEY, new UnauthorizedException());
	}

	protected void sendRedirect(HttpRequest req, HttpResponse resp, String uri) {
		try {
			resp.setStatusCode(302);
			String location = HtmlUtils.escapeHtmlMetaChars(uri);
			resp.setHeader("Location", location);
			LOG.debug("Location: " + location);
		} catch (Exception e) {
			throw new ServiceUnavailableException(e);
		}
	}

	protected void handleLogoutRequest(HttpRequest req, HttpResponse resp, HttpContext context, String username) {
		authentication.logout(req, resp, context, username);
		sessionInvalidate(req);
		context.setAttribute("startUrl", authentication.getStartUrl(req));
		new LoginDispatcher(authentication.getLogoutPage(req)).dispatcher(req, resp, context);
	}

	protected void sessionInvalidate(HttpRequest req) {
	}

	protected void setDefaultContentType(HttpResponse resp) {
		resp.setHeader(HTTP.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
	}

	class LoginDispatcher {
		String path;
		protected VelocityPage page;

		LoginDispatcher(String path) {
			this.path = path;
			Properties props = PropertyUtils.getProperties("velocity.properties");
			page = new VelocityPage(props);
			page.init(docsRoot);
		}

		public void dispatcher(HttpRequest req, HttpResponse resp, HttpContext context) {
			setDefaultContentType(resp);
			String path = getLoginPath();
			LOG.debug("dispatch: " + path);
			VelocityContext ctx = new VelocityContext();
			ctx.put("key", context.getAttribute("key"));
			ctx.put("login_error", context.getAttribute("login_error"));

			String html = page.getPage(req, resp, ctx, path);
			resp.setEntity(new StringEntity(html, "UTF-8"));
		}

		protected String getLoginPath() {
			// return rootPath + path;// "/login/login.jsp";
			return path;
		}
	}
}