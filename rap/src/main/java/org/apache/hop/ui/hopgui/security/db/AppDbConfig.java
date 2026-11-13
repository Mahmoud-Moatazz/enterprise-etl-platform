/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hop.ui.hopgui.security.db;

import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import lombok.Getter;
import org.apache.hop.core.security.repository.AppDbException;

/**
 * Configuration model and parser for application database connectivity and connection pool
 * settings.
 *
 * <p>Validates configuration parameters upon loading without opening network connections. Adheres
 * to fail-secure principles and credential redaction.
 */
@Getter
public class AppDbConfig {

  public enum UserStoreMode {
    FILE,
    DATABASE
  }

  public static final String ENV_USER_STORE_MODE = "HOP_USER_STORE_MODE";
  public static final String ENV_AUTH_DB_URL = "HOP_AUTH_DB_URL";
  public static final String ENV_AUTH_DB_USER = "HOP_AUTH_DB_USER";
  public static final String ENV_AUTH_DB_PASSWORD = "HOP_AUTH_DB_PASSWORD";
  public static final String ENV_AUTH_DB_DRIVER = "HOP_AUTH_DB_DRIVER";
  public static final String ENV_AUTH_DB_TYPE = "HOP_AUTH_DB_TYPE";
  public static final String ENV_POOL_MAX_ACTIVE = "HOP_AUTH_DB_POOL_MAX_ACTIVE";
  public static final String ENV_POOL_INITIAL_SIZE = "HOP_AUTH_DB_POOL_INITIAL_SIZE";
  public static final String ENV_POOL_MIN_IDLE = "HOP_AUTH_DB_POOL_MIN_IDLE";
  public static final String ENV_POOL_MAX_WAIT_MS = "HOP_AUTH_DB_POOL_MAX_WAIT_MS";
  public static final String ENV_POOL_VALIDATION_INTERVAL_MS =
      "HOP_AUTH_DB_POOL_VALIDATION_INTERVAL_MS";
  public static final String ENV_POOL_TEST_ON_BORROW = "HOP_AUTH_DB_POOL_TEST_ON_BORROW";
  public static final String ENV_POOL_VALIDATION_QUERY = "HOP_AUTH_DB_POOL_VALIDATION_QUERY";
  public static final String ENV_STARTUP_RETRY_TIMEOUT_SECONDS =
      "HOP_AUTH_DB_STARTUP_RETRY_TIMEOUT_SECONDS";

  public static final int DEFAULT_MAX_ACTIVE = 20;
  public static final long DEFAULT_MAX_WAIT_MS = 5000L;
  public static final long DEFAULT_VALIDATION_INTERVAL_MS = 30000L;
  public static final boolean DEFAULT_TEST_ON_BORROW = true;
  public static final String DEFAULT_VALIDATION_QUERY = "SELECT 1";
  public static final String DEFAULT_DRIVER_CLASS = "org.postgresql.Driver";
  public static final String DEFAULT_DB_TYPE = "postgresql";
  public static final int DEFAULT_STARTUP_RETRY_TIMEOUT_SECONDS = 30;

  private static final Pattern URL_USERINFO_PASSWORD_PATTERN =
      Pattern.compile("(://[^/?#@:]*:)[^/?#@]*(@)");
  private static final Pattern URL_PARAM_PASSWORD_PATTERN =
      Pattern.compile("([?&](?:password|pwd)=)([^&#]*)", Pattern.CASE_INSENSITIVE);

  private final UserStoreMode userStoreMode;
  private final String url;
  private final String user;
  private final String password;
  private final String driverClassName;
  private final String databaseType;
  private final int maxActive;
  private final int initialSize;
  private final int minIdle;
  private final long maxWaitMillis;
  private final long validationIntervalMillis;
  private final boolean testOnBorrow;
  private final String validationQuery;
  private final int startupRetryTimeoutSeconds;

  private AppDbConfig(
      UserStoreMode userStoreMode,
      String url,
      String user,
      String password,
      String driverClassName,
      String databaseType,
      int maxActive,
      int initialSize,
      int minIdle,
      long maxWaitMillis,
      long validationIntervalMillis,
      boolean testOnBorrow,
      String validationQuery,
      int startupRetryTimeoutSeconds) {
    this.userStoreMode = Objects.requireNonNull(userStoreMode, "userStoreMode cannot be null");
    this.url = url;
    this.user = user;
    this.password = password;
    this.driverClassName = driverClassName;
    this.databaseType = databaseType;
    this.maxActive = maxActive;
    this.initialSize = initialSize;
    this.minIdle = minIdle;
    this.maxWaitMillis = maxWaitMillis;
    this.validationIntervalMillis = validationIntervalMillis;
    this.testOnBorrow = testOnBorrow;
    this.validationQuery = validationQuery;
    this.startupRetryTimeoutSeconds = startupRetryTimeoutSeconds;
  }

  /**
   * Loads configuration from active system environment variables.
   *
   * @return validated AppDbConfig instance
   */
  public static AppDbConfig fromEnvironment() {
    return fromMap(System.getenv());
  }

  /**
   * Creates and validates configuration from the supplied property map.
   *
   * @param properties environment/property map
   * @return validated AppDbConfig instance
   */
  public static AppDbConfig fromMap(Map<String, String> properties) {
    Map<String, String> props = (properties != null) ? properties : Map.of();

    UserStoreMode mode = resolveMode(props.get(ENV_USER_STORE_MODE));
    if (mode == UserStoreMode.FILE) {
      return new AppDbConfig(
          UserStoreMode.FILE, null, null, null, null, null, 0, 0, 0, 0L, 0L, false, null, 0);
    }

    // DATABASE Mode Validation
    String url = getTrimmedOrNull(props.get(ENV_AUTH_DB_URL));
    if (url == null) {
      throw new AppDbException("HOP_USER_STORE_MODE is DATABASE, but HOP_AUTH_DB_URL is unset.");
    }
    if (!url.toLowerCase().startsWith("jdbc:")) {
      throw new AppDbException(
          "HOP_AUTH_DB_URL must be a valid JDBC URL starting with 'jdbc:'. Found: '"
              + maskUrl(url)
              + "'");
    }

    String dbUser = getTrimmedOrNull(props.get(ENV_AUTH_DB_USER));
    if (dbUser == null) {
      throw new AppDbException("HOP_USER_STORE_MODE is DATABASE, but HOP_AUTH_DB_USER is unset.");
    }

    String rawPassword = props.get(ENV_AUTH_DB_PASSWORD);
    String dbPassword = (rawPassword != null) ? rawPassword : "";

    String driver = getTrimmedOrDefault(props.get(ENV_AUTH_DB_DRIVER), DEFAULT_DRIVER_CLASS);
    String dbType = getTrimmedOrDefault(props.get(ENV_AUTH_DB_TYPE), DEFAULT_DB_TYPE);

    int maxActive =
        parseInteger(
            props.get(ENV_POOL_MAX_ACTIVE), ENV_POOL_MAX_ACTIVE, DEFAULT_MAX_ACTIVE, 1, 500);

    // Dependent pool defaults:
    // If unset, initialSize and minIdle default to min(2, maxActive).
    // If explicitly set, they must be validated against maxActive.
    String rawInitialSize = getTrimmedOrNull(props.get(ENV_POOL_INITIAL_SIZE));
    int initialSize;
    if (rawInitialSize == null) {
      initialSize = Math.min(2, maxActive);
    } else {
      initialSize =
          parseInteger(rawInitialSize, ENV_POOL_INITIAL_SIZE, Math.min(2, maxActive), 0, maxActive);
    }

    String rawMinIdle = getTrimmedOrNull(props.get(ENV_POOL_MIN_IDLE));
    int minIdle;
    if (rawMinIdle == null) {
      minIdle = Math.min(2, maxActive);
    } else {
      minIdle = parseInteger(rawMinIdle, ENV_POOL_MIN_IDLE, Math.min(2, maxActive), 0, maxActive);
    }

    long maxWaitMillis =
        parseLong(
            props.get(ENV_POOL_MAX_WAIT_MS),
            ENV_POOL_MAX_WAIT_MS,
            DEFAULT_MAX_WAIT_MS,
            100L,
            60000L);

    long validationIntervalMillis =
        parseLong(
            props.get(ENV_POOL_VALIDATION_INTERVAL_MS),
            ENV_POOL_VALIDATION_INTERVAL_MS,
            DEFAULT_VALIDATION_INTERVAL_MS,
            1000L,
            600000L);

    boolean testOnBorrow =
        parseBoolean(
            props.get(ENV_POOL_TEST_ON_BORROW), ENV_POOL_TEST_ON_BORROW, DEFAULT_TEST_ON_BORROW);

    String validationQuery =
        getTrimmedOrDefault(props.get(ENV_POOL_VALIDATION_QUERY), DEFAULT_VALIDATION_QUERY);

    int startupRetryTimeoutSeconds =
        parseInteger(
            props.get(ENV_STARTUP_RETRY_TIMEOUT_SECONDS),
            ENV_STARTUP_RETRY_TIMEOUT_SECONDS,
            DEFAULT_STARTUP_RETRY_TIMEOUT_SECONDS,
            1,
            300);

    return new AppDbConfig(
        UserStoreMode.DATABASE,
        url,
        dbUser,
        dbPassword,
        driver,
        dbType,
        maxActive,
        initialSize,
        minIdle,
        maxWaitMillis,
        validationIntervalMillis,
        testOnBorrow,
        validationQuery,
        startupRetryTimeoutSeconds);
  }

  public boolean isDatabaseMode() {
    return userStoreMode == UserStoreMode.DATABASE;
  }

  public boolean isFileMode() {
    return userStoreMode == UserStoreMode.FILE;
  }

  public String getMaskedUrl() {
    return maskUrl(url);
  }

  private static UserStoreMode resolveMode(String rawMode) {
    if (rawMode == null || rawMode.isBlank()) {
      return UserStoreMode.FILE;
    }
    String trimmed = rawMode.trim();
    if ("FILE".equalsIgnoreCase(trimmed)) {
      return UserStoreMode.FILE;
    }
    if ("DATABASE".equalsIgnoreCase(trimmed)) {
      return UserStoreMode.DATABASE;
    }
    throw new AppDbException(
        "Invalid HOP_USER_STORE_MODE: '" + trimmed + "'. Allowed values are FILE or DATABASE.");
  }

  private static String getTrimmedOrNull(String val) {
    if (val == null || val.isBlank()) {
      return null;
    }
    return val.trim();
  }

  private static String getTrimmedOrDefault(String val, String defaultVal) {
    if (val == null || val.isBlank()) {
      return defaultVal;
    }
    return val.trim();
  }

  private static int parseInteger(
      String raw, String propertyName, int defaultValue, int min, int max) {
    if (raw == null || raw.isBlank()) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(raw.trim());
      if (parsed < min || parsed > max) {
        throw new AppDbException(
            String.format(
                "%s must be between %d and %d. Found: %d", propertyName, min, max, parsed));
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new AppDbException(
          String.format("Invalid integer for %s: '%s'", propertyName, raw.trim()), e);
    }
  }

  private static long parseLong(
      String raw, String propertyName, long defaultValue, long min, long max) {
    if (raw == null || raw.isBlank()) {
      return defaultValue;
    }
    try {
      long parsed = Long.parseLong(raw.trim());
      if (parsed < min || parsed > max) {
        throw new AppDbException(
            String.format(
                "%s must be between %d and %d. Found: %d", propertyName, min, max, parsed));
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new AppDbException(
          String.format("Invalid long integer for %s: '%s'", propertyName, raw.trim()), e);
    }
  }

  private static boolean parseBoolean(String raw, String propertyName, boolean defaultValue) {
    if (raw == null || raw.isBlank()) {
      return defaultValue;
    }
    String trimmed = raw.trim();
    if ("true".equalsIgnoreCase(trimmed)) {
      return true;
    }
    if ("false".equalsIgnoreCase(trimmed)) {
      return false;
    }
    throw new AppDbException(
        String.format(
            "Invalid boolean for %s: '%s'. Allowed values are 'true' or 'false'.",
            propertyName, trimmed));
  }

  public static String maskUrl(String rawUrl) {
    if (rawUrl == null) {
      return "";
    }
    String masked = URL_USERINFO_PASSWORD_PATTERN.matcher(rawUrl).replaceAll("$1****$2");
    return URL_PARAM_PASSWORD_PATTERN.matcher(masked).replaceAll("$1****");
  }

  @Override
  public String toString() {
    if (userStoreMode == UserStoreMode.FILE) {
      return "AppDbConfig(userStoreMode=FILE)";
    }
    String maskedPassword = (password != null && !password.isEmpty()) ? "[PROTECTED]" : "[UNSET]";
    return String.format(
        "AppDbConfig(userStoreMode=DATABASE, url='%s', user='%s', password=%s, driverClassName='%s', databaseType='%s', maxActive=%d, initialSize=%d, minIdle=%d, maxWaitMillis=%d, validationIntervalMillis=%d, testOnBorrow=%b, validationQuery='%s', startupRetryTimeoutSeconds=%d)",
        maskUrl(url),
        user,
        maskedPassword,
        driverClassName,
        databaseType,
        maxActive,
        initialSize,
        minIdle,
        maxWaitMillis,
        validationIntervalMillis,
        testOnBorrow,
        validationQuery,
        startupRetryTimeoutSeconds);
  }
}
