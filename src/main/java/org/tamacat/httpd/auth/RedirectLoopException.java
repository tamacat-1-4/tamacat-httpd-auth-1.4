package org.tamacat.httpd.auth;

public class RedirectLoopException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public RedirectLoopException() {}

	public RedirectLoopException(String message) {
		super(message);
	}

	public RedirectLoopException(Throwable cause) {
		super(cause);
	}

	public RedirectLoopException(String message, Throwable cause) {
		super(message, cause);
	}

	public RedirectLoopException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
