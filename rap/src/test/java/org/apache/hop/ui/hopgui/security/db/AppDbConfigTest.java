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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.apache.hop.core.security.repository.AppDbException;
import org.junit.jupiter.api.Test;

class AppDbConfigTest {

  @Test
  void testDefaultModeIsFileWhenUnset() {
    AppDbConfig config = AppDbConfig.fromMap(Map.of());
    assertEquals(AppDbConfig.UserStoreMode.FILE, config.getUserStoreMode());
    assertTrue(config.isFileMode());
    assertFalse(config.isDatabaseMode());
    assertNull(config.getUrl());
    assertNull(config.getUser());
    assertEquals("AppDbConfig(userStoreMode=FILE)", config.toString());
  }

  @Test
  void testNullMapDefaultsToFileMode() {
    AppDbConfig config = AppDbConfig.fromMap(null);
    assertEquals(AppDbConfig.UserStoreMode.FILE, config.getUserStoreMode());
    assertTrue(config.isFileMode());
    assertFalse(config.isDatabaseMode());
  }

  @Test
  void testExplicitFileModeParsing() {
    for (String val : new String[] {"FILE", "file", "  File  ", "   "}) {
      Map<String, String> map = new HashMap<>();
      map.put(AppDbConfig.ENV_USER_STORE_MODE, val);
      AppDbConfig config = AppDbConfig.fromMap(map);
      assertEquals(AppDbConfig.UserStoreMode.FILE, config.getUserStoreMode());
      assertTrue(config.isFileMode());
    }
  }

  @Test
  void testInvalidModeThrowsAppDbException() {
    for (String invalid : new String[] {"SQL", "MONGO", "REDIS", "true", "1", "DB"}) {
      Map<String, String> map = Map.of(AppDbConfig.ENV_USER_STORE_MODE, invalid);
      AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
      assertTrue(ex.getMessage().contains("Invalid HOP_USER_STORE_MODE"));
      assertTrue(ex.getMessage().contains("Allowed values are FILE or DATABASE"));
    }
  }

  @Test
  void testDatabaseModeValidConfigurationWithDefaults() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop_users",
            AppDbConfig.ENV_AUTH_DB_USER, "hop_admin",
            AppDbConfig.ENV_AUTH_DB_PASSWORD, "superSecret123");

    AppDbConfig config = AppDbConfig.fromMap(map);
    assertTrue(config.isDatabaseMode());
    assertFalse(config.isFileMode());
    assertEquals("jdbc:postgresql://localhost:5432/hop_users", config.getUrl());
    assertEquals("hop_admin", config.getUser());
    assertEquals("superSecret123", config.getPassword());
    assertEquals("org.postgresql.Driver", config.getDriverClassName());
    assertEquals("postgresql", config.getDatabaseType());
    assertEquals(20, config.getMaxActive());
    assertEquals(2, config.getInitialSize());
    assertEquals(2, config.getMinIdle());
    assertEquals(5000L, config.getMaxWaitMillis());
    assertEquals(30000L, config.getValidationIntervalMillis());
    assertTrue(config.isTestOnBorrow());
    assertEquals("SELECT 1", config.getValidationQuery());
    assertEquals(30, config.getStartupRetryTimeoutSeconds());
  }

  @Test
  void testDatabaseModeMissingUrlThrows() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_USER, "hop_admin");

    AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
    assertTrue(ex.getMessage().contains("HOP_AUTH_DB_URL is unset"));
  }

  @Test
  void testDatabaseModeInvalidUrlSchemeThrows() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "postgresql://localhost:5432/hop_users",
            AppDbConfig.ENV_AUTH_DB_USER, "hop_admin");

    AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
    assertTrue(ex.getMessage().contains("must be a valid JDBC URL starting with 'jdbc:'"));
  }

  @Test
  void testDatabaseModeMissingUserThrows() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop_users");

    AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
    assertTrue(ex.getMessage().contains("HOP_AUTH_DB_USER is unset"));
  }

  @Test
  void testDatabaseModeBlankPasswordAllowed() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop_users",
            AppDbConfig.ENV_AUTH_DB_USER, "hop_admin");

    AppDbConfig config = AppDbConfig.fromMap(map);
    assertNotNull(config.getPassword());
    assertEquals("", config.getPassword());
  }

  @Test
  void testDependentPoolDefaultsWhenUnset() {
    // 1. Default maxActive (20) -> initialSize = min(2, 20) = 2, minIdle = min(2, 20) = 2
    Map<String, String> baseMap =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop");
    AppDbConfig defaultConfig = AppDbConfig.fromMap(baseMap);
    assertEquals(20, defaultConfig.getMaxActive());
    assertEquals(2, defaultConfig.getInitialSize());
    assertEquals(2, defaultConfig.getMinIdle());

    // 2. Constrained maxActive = 1 -> initialSize = min(2, 1) = 1, minIdle = min(2, 1) = 1
    Map<String, String> constrainedMap = new HashMap<>(baseMap);
    constrainedMap.put(AppDbConfig.ENV_POOL_MAX_ACTIVE, "1");
    AppDbConfig constrainedConfig = AppDbConfig.fromMap(constrainedMap);
    assertEquals(1, constrainedConfig.getMaxActive());
    assertEquals(1, constrainedConfig.getInitialSize());
    assertEquals(1, constrainedConfig.getMinIdle());
  }

  @Test
  void testExplicitPoolValuesPreserved() {
    Map<String, String> map = new HashMap<>();
    map.put(AppDbConfig.ENV_USER_STORE_MODE, "DATABASE");
    map.put(AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop");
    map.put(AppDbConfig.ENV_AUTH_DB_USER, "hop");
    map.put(AppDbConfig.ENV_POOL_MAX_ACTIVE, "10");
    map.put(AppDbConfig.ENV_POOL_INITIAL_SIZE, "5");
    map.put(AppDbConfig.ENV_POOL_MIN_IDLE, "3");
    map.put(AppDbConfig.ENV_POOL_MAX_WAIT_MS, "10000");
    map.put(AppDbConfig.ENV_POOL_VALIDATION_INTERVAL_MS, "45000");
    map.put(AppDbConfig.ENV_POOL_TEST_ON_BORROW, "false");
    map.put(AppDbConfig.ENV_POOL_VALIDATION_QUERY, "SELECT version()");
    map.put(AppDbConfig.ENV_STARTUP_RETRY_TIMEOUT_SECONDS, "60");

    AppDbConfig config = AppDbConfig.fromMap(map);
    assertEquals(10, config.getMaxActive());
    assertEquals(5, config.getInitialSize());
    assertEquals(3, config.getMinIdle());
    assertEquals(10000L, config.getMaxWaitMillis());
    assertEquals(45000L, config.getValidationIntervalMillis());
    assertFalse(config.isTestOnBorrow());
    assertEquals("SELECT version()", config.getValidationQuery());
    assertEquals(60, config.getStartupRetryTimeoutSeconds());
  }

  @Test
  void testExplicitInitialSizeExceedingMaxActiveThrows() {
    // maxActive=1, explicit initialSize=2 must fail validation
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop",
            AppDbConfig.ENV_POOL_MAX_ACTIVE, "1",
            AppDbConfig.ENV_POOL_INITIAL_SIZE, "2");

    AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
    assertTrue(ex.getMessage().contains("HOP_AUTH_DB_POOL_INITIAL_SIZE"));
    assertTrue(ex.getMessage().contains("must be between 0 and 1"));
  }

  @Test
  void testExplicitMinIdleExceedingMaxActiveThrows() {
    // maxActive=1, explicit minIdle=2 must fail validation
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop",
            AppDbConfig.ENV_POOL_MAX_ACTIVE, "1",
            AppDbConfig.ENV_POOL_MIN_IDLE, "2");

    AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map));
    assertTrue(ex.getMessage().contains("HOP_AUTH_DB_POOL_MIN_IDLE"));
    assertTrue(ex.getMessage().contains("must be between 0 and 1"));
  }

  @Test
  void testInvalidPoolNumbersThrowAppDbException() {
    Map<String, String> base =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop");

    // Non-numeric
    Map<String, String> m1 = new HashMap<>(base);
    m1.put(AppDbConfig.ENV_POOL_MAX_ACTIVE, "not-a-number");
    assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(m1));

    // Zero maxActive
    Map<String, String> m2 = new HashMap<>(base);
    m2.put(AppDbConfig.ENV_POOL_MAX_ACTIVE, "0");
    assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(m2));

    // Negative initialSize
    Map<String, String> m3 = new HashMap<>(base);
    m3.put(AppDbConfig.ENV_POOL_INITIAL_SIZE, "-1");
    assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(m3));

    // Exceed maxActive limit (500)
    Map<String, String> m4 = new HashMap<>(base);
    m4.put(AppDbConfig.ENV_POOL_MAX_ACTIVE, "501");
    assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(m4));
  }

  @Test
  void testPasswordRedactionInToString() {
    Map<String, String> map =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop",
            AppDbConfig.ENV_AUTH_DB_PASSWORD, "mySecretPassword123!");

    AppDbConfig config = AppDbConfig.fromMap(map);
    String str = config.toString();
    assertFalse(str.contains("mySecretPassword123!"));
    assertTrue(str.contains("password=[PROTECTED]"));
  }

  @Test
  void testStrictBooleanParsingForTestOnBorrow() {
    Map<String, String> base =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://localhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "hop");

    // Case-insensitive valid true
    for (String val : new String[] {"true", "True", "TRUE", " true "}) {
      Map<String, String> m = new HashMap<>(base);
      m.put(AppDbConfig.ENV_POOL_TEST_ON_BORROW, val);
      assertTrue(AppDbConfig.fromMap(m).isTestOnBorrow());
    }

    // Case-insensitive valid false
    for (String val : new String[] {"false", "False", "FALSE", " false "}) {
      Map<String, String> m = new HashMap<>(base);
      m.put(AppDbConfig.ENV_POOL_TEST_ON_BORROW, val);
      assertFalse(AppDbConfig.fromMap(m).isTestOnBorrow());
    }

    // Unset or blank uses default (true)
    for (String val : new String[] {null, "", "   "}) {
      Map<String, String> m = new HashMap<>(base);
      if (val != null) {
        m.put(AppDbConfig.ENV_POOL_TEST_ON_BORROW, val);
      }
      assertTrue(AppDbConfig.fromMap(m).isTestOnBorrow());
    }

    // Invalid boolean values must throw AppDbException
    for (String invalid : new String[] {"yes", "no", "1", "0", "on", "off", "invalid"}) {
      Map<String, String> m = new HashMap<>(base);
      m.put(AppDbConfig.ENV_POOL_TEST_ON_BORROW, invalid);
      AppDbException ex = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(m));
      assertTrue(ex.getMessage().contains("Invalid boolean for HOP_AUTH_DB_POOL_TEST_ON_BORROW"));
      assertTrue(ex.getMessage().contains("Allowed values are 'true' or 'false'"));
    }
  }

  @Test
  void testUserinfoCredentialsInJdbcUrlWithAndWithoutPort() {
    // 1. Userinfo with port (reported JDBC format)
    assertEquals(
        "jdbc:postgresql://user:****@host:5432/db",
        AppDbConfig.maskUrl("jdbc:postgresql://user:secretPass@host:5432/db"));

    // 2. Userinfo without port
    assertEquals(
        "jdbc:postgresql://user:****@host/db",
        AppDbConfig.maskUrl("jdbc:postgresql://user:secretPass@host/db"));

    // 3. Userinfo without port, with query parameters
    assertEquals(
        "jdbc:postgresql://user:****@host/db?ssl=true",
        AppDbConfig.maskUrl("jdbc:postgresql://user:secretPass@host/db?ssl=true"));
  }

  @Test
  void testQueryParameterPasswordMasking() {
    // 1. 'password' parameter
    assertEquals(
        "jdbc:postgresql://host:5432/db?password=****",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?password=secret"));

    // 2. 'pwd' parameter
    assertEquals(
        "jdbc:postgresql://host:5432/db?pwd=****",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?pwd=secret"));

    // 3. 'password' parameter followed by additional parameters
    assertEquals(
        "jdbc:postgresql://host:5432/db?password=****&ssl=true&timeout=10",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?password=secret&ssl=true&timeout=10"));

    // 4. 'pwd' parameter preceded and followed by additional parameters
    assertEquals(
        "jdbc:postgresql://host:5432/db?user=admin&pwd=****&ssl=true&timeout=10",
        AppDbConfig.maskUrl(
            "jdbc:postgresql://host:5432/db?user=admin&pwd=secret&ssl=true&timeout=10"));
  }

  @Test
  void testCaseInsensitiveQueryParameterPasswordMasking() {
    assertEquals(
        "jdbc:postgresql://host:5432/db?PASSWORD=****",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?PASSWORD=secret"));

    assertEquals(
        "jdbc:postgresql://host:5432/db?Password=****&ssl=true",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?Password=secret&ssl=true"));

    assertEquals(
        "jdbc:postgresql://host:5432/db?PWD=****",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?PWD=secret"));

    assertEquals(
        "jdbc:postgresql://host:5432/db?Pwd=****&ssl=true",
        AppDbConfig.maskUrl("jdbc:postgresql://host:5432/db?Pwd=secret&ssl=true"));

    // Both userinfo and query parameter password masked together
    assertEquals(
        "jdbc:postgresql://user:****@host:5432/db?PASSWORD=****&ssl=true",
        AppDbConfig.maskUrl(
            "jdbc:postgresql://user:userPass@host:5432/db?PASSWORD=queryPass&ssl=true"));
  }

  @Test
  void testMaskUrlNullAndEmpty() {
    assertEquals("", AppDbConfig.maskUrl(null));
    assertEquals("", AppDbConfig.maskUrl(""));
  }

  @Test
  void testMaskUrlPreservesNonSensitiveComponents() {
    // Standard URL without credentials
    assertEquals(
        "jdbc:postgresql://localhost:5432/hop_users",
        AppDbConfig.maskUrl("jdbc:postgresql://localhost:5432/hop_users"));

    // Query parameters without sensitive fields preserved
    assertEquals(
        "jdbc:postgresql://localhost:5432/hop_users?ssl=true&sslmode=require",
        AppDbConfig.maskUrl("jdbc:postgresql://localhost:5432/hop_users?ssl=true&sslmode=require"));

    // Username only in userinfo (no password) preserved
    assertEquals(
        "jdbc:postgresql://hop@localhost:5432/hop_users",
        AppDbConfig.maskUrl("jdbc:postgresql://hop@localhost:5432/hop_users"));

    // Multi-host cluster URL preserved
    assertEquals(
        "jdbc:postgresql://host1:5432,host2:5432/hop_users",
        AppDbConfig.maskUrl("jdbc:postgresql://host1:5432,host2:5432/hop_users"));
  }

  @Test
  void testOriginalUrlNeverExposedInExceptionsOrDiagnostics() {
    // 1. Exception thrown on invalid URL scheme with userinfo credentials
    Map<String, String> map1 =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "postgresql://user:secretPass@localhost:5432/db",
            AppDbConfig.ENV_AUTH_DB_USER, "admin");

    AppDbException ex1 = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map1));
    assertFalse(ex1.getMessage().contains("secretPass"));
    assertTrue(ex1.getMessage().contains("postgresql://user:****@localhost:5432/db"));

    // 2. Exception thrown on invalid URL scheme with query parameter password
    Map<String, String> map2 =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "http://localhost:5432/db?password=paramSecret",
            AppDbConfig.ENV_AUTH_DB_USER, "admin");

    AppDbException ex2 = assertThrows(AppDbException.class, () -> AppDbConfig.fromMap(map2));
    assertFalse(ex2.getMessage().contains("paramSecret"));
    assertTrue(ex2.getMessage().contains("http://localhost:5432/db?password=****"));

    // 3. Diagnostics via toString() masks both URL credentials and standalone password
    Map<String, String> map3 =
        Map.of(
            AppDbConfig.ENV_USER_STORE_MODE, "DATABASE",
            AppDbConfig.ENV_AUTH_DB_URL, "jdbc:postgresql://admin:urlPass@dbhost:5432/hop",
            AppDbConfig.ENV_AUTH_DB_USER, "admin",
            AppDbConfig.ENV_AUTH_DB_PASSWORD, "standalonePass");

    AppDbConfig config = AppDbConfig.fromMap(map3);
    String diag = config.toString();
    assertFalse(diag.contains("urlPass"));
    assertFalse(diag.contains("standalonePass"));
    assertTrue(diag.contains("jdbc:postgresql://admin:****@dbhost:5432/hop"));
    assertTrue(diag.contains("password=[PROTECTED]"));
    assertEquals("jdbc:postgresql://admin:****@dbhost:5432/hop", config.getMaskedUrl());
  }
}
