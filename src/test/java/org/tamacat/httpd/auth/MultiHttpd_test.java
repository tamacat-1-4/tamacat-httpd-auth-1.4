/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import org.tamacat.di.DI;
import org.tamacat.di.DIContainer;
import org.tamacat.httpd.core.HttpEngine;

/**
 * <p>
 * It is the start class of the http server. The component setting in
 * {@code components.xml}.
 */
public class MultiHttpd_test {

	public static final String[] XML = {"httpd.xml", "httpsd.xml"};
	private static final String DEFAULT_SERVER_KEY = "server";

	/**
	 * <p>
	 * Http/Https server is started.
	 */
	public static void main(String[] args) {
		String serverKey = DEFAULT_SERVER_KEY;
		for (String config : XML) {
			DIContainer di = DI.configure(config);
			if (di == null)
				throw new IllegalArgumentException(config + " is not found.");
			HttpEngine server = di.getBean(serverKey, HttpEngine.class);
			if (server == null)
				throw new IllegalArgumentException();
			Thread t = new Thread(server);
			t.start();
		}
	}
}
