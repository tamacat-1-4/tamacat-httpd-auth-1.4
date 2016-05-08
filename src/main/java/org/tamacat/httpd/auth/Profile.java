package org.tamacat.httpd.auth;

public interface Profile {

	String val(String key);
	
	Profile val(String key, String value);
	
	String[] keys();
}
