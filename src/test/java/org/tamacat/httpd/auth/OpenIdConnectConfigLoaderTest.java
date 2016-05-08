package org.tamacat.httpd.auth;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;

public class OpenIdConnectConfigLoaderTest {

	static final Log LOG = LogFactory.getLog(OpenIdConnectConfigLoaderTest.class);
	
	@Test
	public void testLoad() {
		OpenIdConnectConfigLoader loader = new OpenIdConnectConfigLoader();
		Map<String, OpenIdConnectConfig> configs = loader.load("openid-connect-config.json");
		//for (OpenIdConnectConfig config : configs.values()) {
		//	LOG.debug(config);
		//}

		OpenIdConnectConfig config = configs.get("test01.example.com");
		assertEquals("http://sso.example.local/oauth2/authorize", config.getAuthorizationEndpoint());
		assertEquals("http://sso.example.local/oauth2/token", config.getTokenEndpoint());
		
		Profile profile = config.getProfile();

		assertEquals("user_name", profile.keys()[0]);
		assertEquals("email", profile.keys()[1]);
	}
}
