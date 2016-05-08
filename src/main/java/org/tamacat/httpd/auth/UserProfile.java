package org.tamacat.httpd.auth;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

public class UserProfile implements Profile {

	protected Set<String> keys = new LinkedHashSet<>();
	
	protected LinkedHashMap<String, String> profile = new LinkedHashMap<>();
	
	@Override
	public String val(String key) {
		return profile.get(key);
	}
	
	@Override
	public Profile val(String key, String value) {
		profile.put(key, value);
		return this;
	}

	@Override
	public String[] keys() {
		return keys.toArray(new String[keys.size()]);
	}
	
	public Profile addKeys(String... keys) {
		for (String key : keys) {
			this.keys.add(key);
		}
		return this;
	}

	@Override
	public String toString() {
		return "UserProfile [keys=" + keys + ", profile=" + profile + "]";
	}
}
