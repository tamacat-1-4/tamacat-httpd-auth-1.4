/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

public class OpenIdConnectConfig {

	protected String id;
	protected String domain;

	protected String authorizationEndpoint;
	protected String tokenEndpoint;
	protected String userInfoEndpoint;
	protected String endSessionEndpoint;
	protected String checkSessionIframe;
	protected String callbackUri;
	protected String redirectUri;
	protected String registrationUri;
	protected String serviceUri;
	protected String clientId;
	protected String clientSecret;

	protected String upn;
	protected Profile profile;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public Profile getProfile() {
		return profile;
	}

	public void setProfile(Profile profile) {
		this.profile = profile;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getCallbackUri() {
		return callbackUri;
	}

	public void setCallbackUri(String callbackUri) {
		this.callbackUri = callbackUri;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public String getRegistrationUri() {
		return registrationUri;
	}

	public void setRegistrationUri(String registrationUri) {
		this.registrationUri = registrationUri;
	}

	public String getServiceUri() {
		return serviceUri;
	}

	public void setServiceUri(String serviceUri) {
		this.serviceUri = serviceUri;
	}

	public String getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}

	public void setAuthorizationEndpoint(String authorizationEndpoint) {
		this.authorizationEndpoint = authorizationEndpoint;
	}

	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	public String getUserInfoEndpoint() {
		return userInfoEndpoint;
	}

	public void setUserInfoEndpoint(String userInfoEndpoint) {
		this.userInfoEndpoint = userInfoEndpoint;
	}

	public String getEndSessionEndpoint() {
		return endSessionEndpoint;
	}

	public void setEndSessionEndpoint(String endSessionEndpoint) {
		this.endSessionEndpoint = endSessionEndpoint;
	}

	public String getCheckSessionIframe() {
		return checkSessionIframe;
	}

	public void setCheckSessionIframe(String checkSessionIframe) {
		this.checkSessionIframe = checkSessionIframe;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getUpn() {
		return upn;
	}

	public void setUpn(String upn) {
		this.upn = upn;
	}

	@Override
	public String toString() {
		return "OpenIdConnectConfig [id=" + id + ", domain=" + domain
				+ ", authorizationEndpoint=" + authorizationEndpoint
				+ ", tokenEndpoint=" + tokenEndpoint + ", userInfoEndpoint="
				+ userInfoEndpoint + ", endSessionEndpoint="
				+ endSessionEndpoint + ", checkSessionIframe="
				+ checkSessionIframe + ", callbackUri=" + callbackUri
				+ ", redirectUri=" + redirectUri + ", registrationUri="
				+ registrationUri + ", serviceUri=" + serviceUri
				+ ", clientId=" + clientId + ", clientSecret=" + clientSecret
				+ ", upn=" + upn + ", profile=" + profile + "]";
	}
}
