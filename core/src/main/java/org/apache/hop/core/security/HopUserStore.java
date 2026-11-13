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

package org.apache.hop.core.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.apache.hop.core.Const;
import org.apache.hop.core.logging.LogChannel;
import org.apache.hop.core.security.repository.IHopUserRepository;
import org.apache.hop.core.security.repository.JsonFileHopUserRepository;

/**
 * Domain service for Hop-managed authentication and user management.
 *
 * <p>Authentication, password hashing, and role expansion are orchestrated here, while persistence
 * is delegated to an active {@link IHopUserRepository} (defaulting to {@link
 * JsonFileHopUserRepository}).
 *
 * <p>Bootstrap: when the store is empty and {@code HOP_WEB_ADMIN_USER} / {@code
 * HOP_WEB_ADMIN_PASSWORD} are set (or defaults for local dev when mode is BASIC), a first admin
 * user is created.
 */
public final class HopUserStore {

  public static final String USERS_FILENAME = "users.json";

  public static final String ENV_ADMIN_USER = "HOP_WEB_ADMIN_USER";
  public static final String ENV_ADMIN_PASSWORD = "HOP_WEB_ADMIN_PASSWORD";

  private static final Object LOCK = new Object();
  private static volatile HopUserStore instance;

  private IHopUserRepository repository;

  private HopUserStore() {
    this(new JsonFileHopUserRepository());
  }

  private HopUserStore(IHopUserRepository repository) {
    this.repository = (repository != null) ? repository : new JsonFileHopUserRepository();
  }

  /**
   * @return singleton user store (loaded from repository on first access)
   */
  public static HopUserStore getInstance() {
    HopUserStore local = instance;
    if (local != null) {
      return local;
    }
    synchronized (LOCK) {
      if (instance == null) {
        HopUserStore store = new HopUserStore();
        store.reload();
        instance = store;
      }
      return instance;
    }
  }

  /** Reset singleton (tests and lifecycle reset). */
  public static void reset() {
    synchronized (LOCK) {
      instance = null;
    }
  }

  /**
   * Inject or change the active user repository (e.g. switching to database mode during startup).
   *
   * @param repository the user repository to use
   */
  public void setRepository(IHopUserRepository repository) {
    if (repository == null) {
      throw new IllegalArgumentException("repository cannot be null");
    }
    synchronized (LOCK) {
      // Initialize/reload repository before switching the reference.
      // If reload fails (e.g. storage error or corrupted file), the reference is NOT switched.
      repository.reload();
      this.repository = repository;
    }
  }

  /**
   * @return the active user repository
   */
  public IHopUserRepository getRepository() {
    return repository;
  }

  public static String getUsersFilePath() {
    return Const.HOP_CONFIG_FOLDER
        + Const.FILE_SEPARATOR
        + HopSecurityConfig.SECURITY_FOLDER
        + Const.FILE_SEPARATOR
        + USERS_FILENAME;
  }

  /** Reload users from persistent storage into memory. */
  public void reload() {
    synchronized (LOCK) {
      repository.reload();
    }
  }

  public List<HopUser> listUsers() {
    return repository.listUsers();
  }

  public boolean isEmpty() {
    return repository.isEmpty();
  }

  public Optional<HopUser> findUser(String username) {
    return repository.findByUsername(username);
  }

  /**
   * Authenticate a username/password pair.
   *
   * @param username username
   * @param clearPassword clear-text password
   * @return user if credentials match and account is enabled
   */
  public Optional<HopUser> authenticate(String username, String clearPassword) {
    Optional<HopUser> found = findUser(username);
    if (found.isEmpty()) {
      return Optional.empty();
    }
    HopUser user = found.get();
    if (!user.isEnabled()) {
      return Optional.empty();
    }
    if (!PasswordHasher.verify(clearPassword, user.getPasswordHash())) {
      return Optional.empty();
    }
    return Optional.of(user);
  }

  /**
   * Replace the entire user list (e.g. after an admin UI save). Caller is responsible for password
   * hashes already being set on each user.
   *
   * @param newUsers complete user list (must not be empty for BASIC mode)
   */
  public void replaceAllUsers(List<HopUser> newUsers) {
    synchronized (LOCK) {
      repository.replaceAllUsers(newUsers);
    }
  }

  /**
   * Create or replace a user with a clear-text password (hashed before store).
   *
   * @param username username
   * @param clearPassword clear-text password
   * @param roles Hop role ids
   * @return the stored user
   */
  public HopUser upsertUser(String username, String clearPassword, List<String> roles) {
    if (username == null || username.isBlank()) {
      throw new IllegalArgumentException("username is required");
    }
    if (clearPassword == null || clearPassword.isEmpty()) {
      throw new IllegalArgumentException("password is required");
    }
    String name = username.trim();
    String hash = PasswordHasher.hash(clearPassword);
    List<String> roleList = normalizeRoles(roles);

    synchronized (LOCK) {
      HopUser user = new HopUser(name, hash, roleList);
      user.setEnabled(true);
      return repository.saveUser(user);
    }
  }

  /**
   * Seed four demo users (admin, developer, operator, viewer) when the store is empty. Local/dev
   * only — passwords match usernames.
   *
   * @return true if users were created
   */
  public boolean seedDemoUsersIfEmpty() {
    if (!isEmpty()) {
      return false;
    }
    safeLogBasic(
        "Hop BASIC auth: seeding demo users (admin/developer/operator/viewer — passwords match usernames)");
    upsertUser("admin", "admin", List.of(HopRole.ADMIN.getId()));
    upsertUser("developer", "developer", List.of(HopRole.USER.getId()));
    upsertUser("operator", "operator", List.of(HopRole.OPERATOR.getId()));
    upsertUser("viewer", "viewer", List.of(HopRole.READ_ONLY.getId()));
    return true;
  }

  /**
   * Ensure an admin user exists when the store is empty. Uses env {@link #ENV_ADMIN_USER} / {@link
   * #ENV_ADMIN_PASSWORD}, falling back to {@code admin}/{@code admin} when {@code
   * allowDefaultAdmin} is true (local/dev only).
   *
   * @param allowDefaultAdmin whether to use default admin/admin when env is unset
   * @return true if a user was created
   */
  public boolean bootstrapAdminIfEmpty(boolean allowDefaultAdmin) {
    if (!isEmpty()) {
      return false;
    }
    String user = firstNonBlank(System.getenv(ENV_ADMIN_USER), System.getProperty(ENV_ADMIN_USER));
    String pass =
        firstNonBlank(System.getenv(ENV_ADMIN_PASSWORD), System.getProperty(ENV_ADMIN_PASSWORD));
    if (user == null || pass == null) {
      if (!allowDefaultAdmin) {
        safeLogError(
            "Hop BASIC auth: no users in store and "
                + ENV_ADMIN_USER
                + "/"
                + ENV_ADMIN_PASSWORD
                + " are not set. Refusing to start with an empty user database.",
            null);
        return false;
      }
      user = "admin";
      pass = "admin";
      safeLogBasic(
          "Hop BASIC auth: bootstrapping default admin user (change the password for any shared deployment)");
    } else {
      safeLogBasic("Hop BASIC auth: bootstrapping admin user '" + user + "' from environment");
    }
    upsertUser(user, pass, List.of(HopRole.ADMIN.getId()));
    return true;
  }

  /**
   * Build a {@link HopSecurityContext} for an authenticated store user.
   *
   * @param user authenticated user
   * @return security context
   */
  public static HopSecurityContext toSecurityContext(HopUser user) {
    if (user == null || user.getUsername() == null) {
      return HopSecurityContext.unrestricted();
    }
    Set<HopRole> hopRoles = new LinkedHashSet<>();
    if (user.getRoles() != null) {
      for (String roleId : user.getRoles()) {
        HopRole role = HopRole.fromIdOrAlias(roleId);
        if (role != null) {
          hopRoles.add(role);
        }
      }
    }
    if (hopRoles.isEmpty()) {
      hopRoles.add(HopRole.USER);
    }
    return HopSecurityContext.forUser(user.getUsername(), hopRoles);
  }

  /**
   * Expand Hop role ids to names accepted by {@code isUserInRole} / role collection (includes
   * {@code hop-} prefix aliases).
   *
   * @param roleIds role ids from the user record
   * @return expanded set
   */
  public static Set<String> expandContainerRoleNames(List<String> roleIds) {
    Set<String> expanded = new LinkedHashSet<>();
    if (roleIds == null) {
      return expanded;
    }
    for (String roleId : roleIds) {
      if (roleId == null || roleId.isBlank()) {
        continue;
      }
      expanded.add(roleId);
      HopRole hopRole = HopRole.fromIdOrAlias(roleId);
      if (hopRole != null) {
        expanded.add(hopRole.getId());
        expanded.add("hop-" + hopRole.getId());
        if (hopRole == HopRole.READ_ONLY) {
          expanded.add("hop-readonly");
          expanded.add("readonly");
          expanded.add("read-only");
          expanded.add("viewer");
        }
        if (hopRole == HopRole.ADMIN) {
          expanded.add("admin");
          expanded.add("hop-admin");
        }
        if (hopRole == HopRole.USER) {
          expanded.add("user");
          expanded.add("hop-user");
          expanded.add("apachehop");
        }
        if (hopRole == HopRole.OPERATOR) {
          expanded.add("operator");
          expanded.add("hop-operator");
        }
      }
    }
    return expanded;
  }

  private static List<String> normalizeRoles(List<String> roles) {
    List<String> result = new ArrayList<>();
    if (roles == null || roles.isEmpty()) {
      result.add(HopRole.USER.getId());
      return result;
    }
    for (String role : roles) {
      HopRole hopRole = HopRole.fromIdOrAlias(role);
      if (hopRole != null) {
        String id = hopRole.getId();
        if (!result.contains(id)) {
          result.add(id);
        }
      }
    }
    if (result.isEmpty()) {
      result.add(HopRole.USER.getId());
    }
    return result;
  }

  private static void safeLogBasic(String message) {
    try {
      LogChannel.GENERAL.logBasic(message);
    } catch (Exception ignored) {
      // Log store may be unavailable in unit tests
    }
  }

  private static void safeLogError(String message, Exception e) {
    try {
      if (e != null) {
        LogChannel.GENERAL.logError(message, e);
      } else {
        LogChannel.GENERAL.logError(message);
      }
    } catch (Exception ignored) {
      // Log store may be unavailable in unit tests
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a.trim();
    }
    if (b != null && !b.isBlank()) {
      return b.trim();
    }
    return null;
  }

  /** Retained for backward compatibility with existing callers. */
  @Getter
  @Setter
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class UsersFile {
    private List<HopUser> users = new ArrayList<>();
  }

  /**
   * Apply env/system properties that seed security mode for BASIC auth.
   *
   * @return true if mode was set to BASIC from the environment
   */
  public static boolean applyEnvironmentModeOverride() {
    String modeEnv =
        firstNonBlank(
            System.getenv(HopSecurityBootstrap.ENV_SECURITY_MODE),
            System.getProperty(HopSecurityBootstrap.ENV_SECURITY_MODE));
    if (modeEnv == null) {
      return false;
    }
    HopSecurityConfig.AuthMode mode = HopSecurityConfig.AuthMode.fromString(modeEnv);
    HopSecurityConfig config = HopSecurityConfig.load();
    if (config.getAuthMode() != mode) {
      config.setAuthMode(mode);
      HopSecurityConfig.save(config);
      safeLogBasic(
          "Hop security mode set to "
              + mode.name()
              + " from "
              + HopSecurityBootstrap.ENV_SECURITY_MODE);
    }
    return mode == HopSecurityConfig.AuthMode.BASIC;
  }
}
