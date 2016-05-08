package org.tamacat.httpd.auth;

import java.io.StringReader;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

import org.tamacat.util.ClassUtils;

public class Config_test {

	public static void main(String[] args) throws Exception {
		JsonReader reader = Json.createReader(ClassUtils.getURL("openid-connect-config.json").openStream());
		JsonArray array = reader.readArray();
		OpenIdConnectConfig config = new OpenIdConnectConfig();
		for (JsonValue val : array) {
			if (ValueType.OBJECT == val.getValueType()) {
				String data = val.toString();
				JsonReader r = Json.createReader(new StringReader(data));
				JsonObject o = r.readObject();
				config.setDomain(o.getString("domain"));
				config.setAuthorizationEndpoint(o.getString("authorize_endpoint"));
				config.setTokenEndpoint(o.getString("token_endpoint"));
				//config.setParam("idp", o.getString("idp"));
				config.setClientId(o.getString("client_id"));
				config.setClientSecret(o.getString("client_secret"));
			}
		}
	}
}
