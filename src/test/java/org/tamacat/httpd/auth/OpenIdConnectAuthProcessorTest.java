package org.tamacat.httpd.auth;

import static org.junit.Assert.*;

import java.net.URL;

import org.apache.http.HttpRequest;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.tamacat.httpd.config.DefaultReverseUrl;
import org.tamacat.httpd.config.ReverseUrl;
import org.tamacat.httpd.config.ServerConfig;
import org.tamacat.httpd.config.ServiceType;
import org.tamacat.httpd.config.ServiceUrl;

public class OpenIdConnectAuthProcessorTest {

	ServerConfig config = new ServerConfig();
	ServiceUrl serviceUrl;

	public static HttpRequest createHttpRequest(String method, String uri) {
		if ("POST".equalsIgnoreCase(method)) {
			return new BasicHttpEntityEnclosingRequest(method, uri);
		} else {
			return new BasicHttpRequest(method, uri);
		}
	}

	@Before
	public void setUp() throws Exception {
		serviceUrl = new ServiceUrl(config);
		serviceUrl.setPath("/examples/");
		serviceUrl.setType(ServiceType.REVERSE);
		serviceUrl.setHost(new URL("http://localhost/examples/"));
		ReverseUrl reverseUrl = new DefaultReverseUrl(serviceUrl);
		reverseUrl.setReverse(new URL("http://localhost:8080/examples/"));
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetId() {
		HttpRequest req = createHttpRequest("GET", "/examples/login/test01.example.com/oauth2callback");
		HttpContext context = new BasicHttpContext();
		OpenIdConnectAuthProcessor proc = new OpenIdConnectAuthProcessor();
		proc.setLoginPath("/examples/login");
		proc.init(serviceUrl);

		assertEquals("test01.example.com", proc.getId(req, context));
	}

	@Test
	public void testGetIdWithFQDN() {
		HttpRequest req = createHttpRequest("GET", "http://localhost/examples/login/test01.example.com/oauth2callback");
		HttpContext context = new BasicHttpContext();
		OpenIdConnectAuthProcessor proc = new OpenIdConnectAuthProcessor();
		proc.setLoginPath("/examples/login");
		proc.init(serviceUrl);

		assertEquals("test01.example.com", proc.getId(req, context));
	}

	@Test
	public void testGetIdNone() {
		HttpRequest req = createHttpRequest("GET", "http://localhost/examples/oauth2callback");
		HttpContext context = new BasicHttpContext();
		OpenIdConnectAuthProcessor proc = new OpenIdConnectAuthProcessor();
		proc.init(serviceUrl);

		assertEquals("", proc.getId(req, context));
	}

	@Test
	public void testGetClientId() {
	}

	@Test
	public void testGetUrlforCodeFlowAuth() {
	}
	
	@Test
	public void testSetScope() {
		OpenIdConnectAuthProcessor proc = new OpenIdConnectAuthProcessor();
		proc.setScope("");
		assertEquals(0, proc.scopes.size());
		
		proc.setScope("openid");
		assertEquals(1, proc.scopes.size());
		
		proc.setScope("profile, email");
		assertEquals(2, proc.scopes.size());
		
		proc.setScope("openid,profile,email");
		assertEquals(3, proc.scopes.size());
		
		proc.setScope("openid, profile, email");
		assertEquals(3, proc.scopes.size());
	}
	
	@Test
	public void testSetResponseTypes() {
		OpenIdConnectAuthProcessor proc = new OpenIdConnectAuthProcessor();
		proc.setResponseTypes("");
		assertEquals(0, proc.responseTypes.size());
		
		proc.setResponseTypes("code");
		assertEquals(1, proc.responseTypes.size());
		
		proc.setResponseTypes("code, token");
		assertEquals(2, proc.responseTypes.size());
		
		proc.setResponseTypes("code,token,id_token");
		assertEquals(3, proc.responseTypes.size());
		
		proc.setResponseTypes("code, token, id_token");
		assertEquals(3, proc.responseTypes.size());
	}
}
