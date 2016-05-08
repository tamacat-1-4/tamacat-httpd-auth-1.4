package org.tamacat.httpd.auth;

import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

import org.tamacat.io.RuntimeIOException;
import org.tamacat.util.ClassUtils;
import org.tamacat.util.IOUtils;
import org.tamacat.util.StringUtils;

public class OpenIdConnectConfigLoader {

	static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
	static final String TOKEN_ENDPOINT = "token_endpoint";
	static final String CHECK_SESSION_IFRAME = "check_session_iframe";
	static final String CLIENT_ID = "client_id";
	static final String CLIENT_SECRET = "client_secret";
	static final String CALLBACK_URI = "callback_uri";
	static final String REDIRECT_URI = "redirect_uri";
	static final String REGISTRATION_URI = "registration_uri";
	static final String SERVICE_URI = "service_uri";

	public Map<String, OpenIdConnectConfig> load(String file) {
		Map<String, OpenIdConnectConfig> configs = new LinkedHashMap<>();
		JsonReader reader = null;
		try {
			reader = Json.createReader(ClassUtils.getURL(file).openStream());
			for (JsonValue val : reader.readArray()) {
				if (ValueType.OBJECT == val.getValueType()) {
					String data = val.toString();
					JsonReader r = Json.createReader(new StringReader(data));
					JsonObject o = r.readObject();
					String id = o.getString("id", "");
					String domain = o.getString("domain", "");
					if (StringUtils.isNotEmpty(id) && StringUtils.isNotEmpty(domain)) {
						OpenIdConnectConfig config = new OpenIdConnectConfig();
						config.setId(id);
						config.setDomain(domain);
						config.setAuthorizationEndpoint(o.getString(AUTHORIZATION_ENDPOINT, ""));
						config.setTokenEndpoint(o.getString(TOKEN_ENDPOINT, ""));
						config.setCheckSessionIframe(o.getString(CHECK_SESSION_IFRAME, ""));
						config.setClientId(o.getString(CLIENT_ID, ""));
						config.setClientSecret(o.getString(CLIENT_SECRET, ""));
						config.setCallbackUri(o.getString(CALLBACK_URI, ""));
						config.setRedirectUri(o.getString(REDIRECT_URI, ""));
						config.setRegistrationUri(o.getString(REGISTRATION_URI, ""));
						config.setServiceUri(o.getString(SERVICE_URI, ""));
						//config.setParam("idp", o.getString("idp", ""));
						config.setUpn(o.getString("upn", ""));
						JsonArray keys = o.getJsonArray("profile");
						UserProfile profile = new UserProfile();
						if (keys != null && keys.size() > 0) {
							for (int i=0; i<keys.size(); i++) {
								profile.addKeys(keys.getString(i));
							}
							config.setProfile(profile);
						}
						configs.put(id, config);
					}
				}
			}
		} catch (IOException e) {
			throw new RuntimeIOException(e);
		} finally {
			IOUtils.close(reader);
		}
		return configs;
	}
}
