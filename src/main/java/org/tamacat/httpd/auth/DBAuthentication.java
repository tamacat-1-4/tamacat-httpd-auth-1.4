/*
 * Copyright (c) 2015 tamacat.org
 * All rights reserved.
 */
package org.tamacat.httpd.auth;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.tamacat.dao.DaoFactory;
import org.tamacat.auth.model.CacheSupportLoginUser;
import org.tamacat.auth.model.DefaultUser;
import org.tamacat.auth.model.DefaultUserDao;
import org.tamacat.auth.model.DefaultUserORMapper;
import org.tamacat.auth.model.LoginUser;
import org.tamacat.auth.model.LoginUserCache;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.util.DateUtils;
import org.tamacat.util.StringUtils;
import org.tamacat.util.UniqueCodeGenerator;

public class DBAuthentication extends AbstractAuthentication {

	static final Log LOG = LogFactory.getLog(DBAuthentication.class);

	protected String database = "default";
	protected String tableName = "users";
	protected String tidKey = "tid";
	protected String idKey = "id";
	protected String userKey = "user_id";
	protected String passwordKey = "password";
	protected String saltKey = "salt";
	protected String lastLoginKey = "last_login";
	protected String multiLoginKey = "multi_login";
	protected String loginStatusKey = "login_status";
	protected String roleKey;
	
	protected List<String> columnList = new ArrayList<>();
	
	protected LoginUserCache cache;
	protected int maxCacheSize = 100;
	protected long cacheExpire = 30000;
	
	public void setDatabase(String database) {
		this.database = database;
	}
	
	public void setTableName(String tableName) {
		this.tableName = tableName;
	}

	public void setTidKey(String tidKey) {
		this.tidKey = tidKey;
	}

	public void setIdKey(String idKey) {
		this.idKey = idKey;
	}

	public void setUserKey(String userKey) {
		this.userKey = userKey;
	}

	public void setPasswordKey(String passwordKey) {
		this.passwordKey = passwordKey;
	}

	public void setSaltKey(String saltKey) {
		this.saltKey = saltKey;
	}
	
	public void setRoleKey(String roleKey) {
		this.roleKey = roleKey;
	}
	
	public void setLastLoginKey(String lastLoginKey) {
		this.lastLoginKey = lastLoginKey;
	}
	
	public void setMultiLoginKey(String multiLoginKey) {
		this.multiLoginKey = multiLoginKey;
	}
	
	public void setLoginStatusKey(String loginStatusKey) {
		this.loginStatusKey = loginStatusKey;
	}
	
	public void setColumns(String columns) {
		if (StringUtils.isNotEmpty(columns)) {
			String[] cols = StringUtils.split(columns, ",");
			for (String c : cols) {
				if (StringUtils.isNotEmpty(c)) {
					columnList.add(c);
				}
			}
		}
	}
	
	@Override
	public boolean login(HttpRequest req, HttpResponse resp, HttpContext context, String username, String password) {
		boolean result = super.login(req, resp, context, username, password);
		if (result) {
			updateLastLogin(username, "login");
		}
		return result;
	}
	
	@Override
	public void logout(HttpRequest req, HttpResponse resp, HttpContext context, String username) {
		super.logout(req, resp, context, username);
		updateUserSalt(username, UniqueCodeGenerator.generate(), "logout");
		if (cache != null && StringUtils.isNotEmpty(username)) {
			cache.remove(username);
		}
	}
	
	@Override
	public String check(HttpRequest req, HttpResponse resp,HttpContext context) {
		String username = super.check(req, resp, context);
		if (StringUtils.isNotEmpty(username) && useSingleSignOn) {
			LoginUser user = getUser(username);
			if (user != null) {
				context.setAttribute(LOGIN, username);
				context.setAttribute(USER, user);
				username = user.getUserId();
				resp.setHeader(reverseProxyUserHeader, username);
				return username;
			}
		}
		return null;
	}
	
	@Override
	protected String getUserSalt(String username) {
		DefaultUserDao dao = DaoFactory.getDao(DefaultUserDao.class);
		try {
			dao.setDatabase(database);
			DefaultUser user = new DefaultUser(tableName, tidKey, idKey, userKey, passwordKey, saltKey, roleKey,
				lastLoginKey, multiLoginKey, loginStatusKey, columnList.toArray(new String[columnList.size()]));
			user.val(user.getColumn(userKey), username);
			DefaultUser result = dao.search(user);
			
			if (result != null && StringUtils.isNotEmpty(user.getColumn(userKey))) {
				return result.val(user.getColumn(saltKey));
			}
		} finally {
			if (dao != null) {
				dao.release();
			}
		}
		return "";
	}

	@Override
	public LoginUser getUser(String username) {
		if (cache != null) {
			CacheSupportLoginUser u = cache.get(username);
			if (u != null) return u;
		}
		DefaultUserDao dao = DaoFactory.getDao(DefaultUserDao.class);
		try {
			dao.setDatabase(database);
			DefaultUser user = new DefaultUser(tableName, tidKey, idKey, userKey, passwordKey, saltKey, roleKey, 
				lastLoginKey, multiLoginKey, loginStatusKey, columnList.toArray(new String[columnList.size()]));
			user.val(user.getColumn(userKey), username);
			DefaultUser result = dao.search(user);
			if (cache != null && result != null && result instanceof CacheSupportLoginUser) {
				cache.put(username, (CacheSupportLoginUser) result);
			}
			return result;
		} finally {
			if (dao != null) {
				dao.release();
			}
		}
	}
	
	protected int updateUserSalt(String username, String salt, String loginStatus) {
		DefaultUserDao dao = DaoFactory.getDao(DefaultUserDao.class);
		try {
			dao.setDatabase(database);
			DefaultUser user = new DefaultUser(tableName, tidKey, idKey, userKey, passwordKey, saltKey, roleKey,
				lastLoginKey, multiLoginKey, loginStatusKey, columnList.toArray(new String[columnList.size()]));
			dao.setORMapper(new DefaultUserORMapper(user));
			user.val(user.getColumn(userKey), username);
			DefaultUser result = dao.search(user);
			
			if (result != null && StringUtils.isNotEmpty(user.getColumn(userKey))) {
				result.val(user.getColumn(lastLoginKey), DateUtils.getTimestamp("yyyy-MM-dd HH:mm:ss"));
				result.val(user.getColumn(loginStatusKey), loginStatus);
				if (result.isMultiLoginAllowed()) {
					return dao.updateUserLastLogin(result);
				} else {
					result.val(user.getColumn(saltKey), salt);
					return dao.updateUserSalt(result);
				}
			}
			return 0;
		} finally {
			if (dao != null) {
				dao.release();
			}
		}
	}
	
	protected int updateLastLogin(String username, String loginStatus) {
		DefaultUserDao dao = DaoFactory.getDao(DefaultUserDao.class);
		try {
			dao.setDatabase(database);
			DefaultUser user = new DefaultUser(tableName, tidKey, idKey, userKey, passwordKey, saltKey, roleKey,
				lastLoginKey, multiLoginKey, loginStatusKey, columnList.toArray(new String[columnList.size()]));
			dao.setORMapper(new DefaultUserORMapper(user));
			
			user.val(user.getColumn(userKey), username);
			DefaultUser result = dao.search(user);
			
			if (result != null && StringUtils.isNotEmpty(user.getColumn(userKey))) {
				result.val(user.getColumn(lastLoginKey), DateUtils.getTimestamp("yyyy-MM-dd HH:mm:ss"));
				result.val(user.getColumn(loginStatusKey), loginStatus);
				return dao.updateUserLastLogin(result);
			}
			return 0;
		} finally {
			if (dao != null) {
				dao.release();
			}
		}
	}
	
	public void init() {
		if (maxCacheSize > 0 && cacheExpire > 0) {
			cache = new LoginUserCache(maxCacheSize, cacheExpire);
		} else {
			cache = null;
		}
	}
	
	public void setMaxCacheSize(int maxCacheSize) {
		this.maxCacheSize = maxCacheSize;
		init();
	}

	public void setCacheExpire(long cacheExpire) {
		this.cacheExpire = cacheExpire;
		init();
	}
}
