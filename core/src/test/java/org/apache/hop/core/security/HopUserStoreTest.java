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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.vfs2.FileObject;
import org.apache.hop.core.security.repository.IHopUserRepository;
import org.apache.hop.core.security.repository.JsonFileHopUserRepository;
import org.apache.hop.core.vfs.HopVfs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HopUserStoreTest {

  @TempDir Path tempDir;

  private String previousConfigFolder;

  private void deleteStoreFileSilently() {
    try {
      String path = HopUserStore.getUsersFilePath();
      if (HopVfs.fileExists(path)) {
        FileObject file = HopVfs.getFileObject(path);
        file.delete();
      }
    } catch (Exception ignored) {
      // Ignored for tests
    }
  }

  @BeforeEach
  void setConfigFolder() {
    previousConfigFolder = System.getProperty("HOP_CONFIG_FOLDER");
    System.setProperty("HOP_CONFIG_FOLDER", tempDir.toAbsolutePath().toString());
    deleteStoreFileSilently();
    HopUserStore.reset();
    HopSecurityConfig.clearCache();
    HopSecurityBootstrap.reset();
  }

  @AfterEach
  void restore() {
    deleteStoreFileSilently();
    HopUserStore.reset();
    HopSecurityConfig.clearCache();
    HopSecurityBootstrap.reset();
    if (previousConfigFolder == null) {
      System.clearProperty("HOP_CONFIG_FOLDER");
    } else {
      System.setProperty("HOP_CONFIG_FOLDER", previousConfigFolder);
    }
  }

  @Test
  void authenticateAndRoles() {
    HopUserStore store = HopUserStore.getInstance();
    store.upsertUser("alice", "pw", List.of("operator"));
    assertTrue(store.authenticate("alice", "pw").isPresent());
    assertTrue(store.authenticate("alice", "wrong").isEmpty());
    assertTrue(store.authenticate("nobody", "pw").isEmpty());

    HopUser user = store.findUser("alice").orElseThrow();
    HopSecurityContext ctx = HopUserStore.toSecurityContext(user);
    assertEquals("alice", ctx.getUsername());
    assertTrue(ctx.allows(Permission.RUN_EXECUTE));
    assertFalse(ctx.allows(Permission.FILE_SAVE));

    Set<String> expanded = HopUserStore.expandContainerRoleNames(user.getRoles());
    assertTrue(expanded.contains("operator") || expanded.contains("hop-operator"));
  }

  @Test
  void seedDemoUsers() {
    HopUserStore store = HopUserStore.getInstance();
    store.seedDemoUsersIfEmpty();
    if (store.findUser("viewer").isEmpty()) {
      store.upsertUser("viewer", "viewer", List.of("readonly"));
    }
    assertTrue(store.authenticate("viewer", "viewer").isPresent());
    HopSecurityContext ctx = HopUserStore.toSecurityContext(store.findUser("viewer").orElseThrow());
    assertFalse(ctx.allows(Permission.RUN_EXECUTE));
    assertTrue(ctx.allows(Permission.FILE_VIEW));
  }

  @Test
  void passwordHasherRoundTripFileFormat() throws Exception {
    String hash = PasswordHasher.hash("demo");
    Path file = tempDir.resolve("hash.txt");
    Files.writeString(file, hash);
    String loaded = Files.readString(file).trim();
    assertTrue(PasswordHasher.verify("demo", loaded));
  }

  @Test
  void testDefaultRepositoryIsJsonFileHopUserRepository() {
    HopUserStore store = HopUserStore.getInstance();
    assertNotNull(store.getRepository());
    assertTrue(store.getRepository() instanceof JsonFileHopUserRepository);
  }

  @Test
  void testCustomRepositoryInjection() {
    HopUserStore store = HopUserStore.getInstance();

    // In-memory dummy repository to verify delegation
    List<HopUser> memUsers = new ArrayList<>();
    IHopUserRepository customRepo =
        new IHopUserRepository() {
          @Override
          public void reload() {}

          @Override
          public List<HopUser> listUsers() {
            return List.copyOf(memUsers);
          }

          @Override
          public boolean isEmpty() {
            return memUsers.isEmpty();
          }

          @Override
          public Optional<HopUser> findByUsername(String username) {
            return memUsers.stream()
                .filter(u -> u.getUsername().equalsIgnoreCase(username))
                .findFirst();
          }

          @Override
          public HopUser saveUser(HopUser user) {
            memUsers.removeIf(u -> u.getUsername().equalsIgnoreCase(user.getUsername()));
            memUsers.add(user);
            return user;
          }

          @Override
          public void replaceAllUsers(List<HopUser> users) {
            memUsers.clear();
            if (users != null) {
              memUsers.addAll(users);
            }
          }

          @Override
          public boolean deleteUser(String username) {
            return memUsers.removeIf(u -> u.getUsername().equalsIgnoreCase(username));
          }
        };

    store.setRepository(customRepo);
    assertEquals(customRepo, store.getRepository());
    assertTrue(store.isEmpty());

    store.upsertUser("customUser", "secret123", List.of("admin"));
    assertFalse(store.isEmpty());
    assertEquals(1, store.listUsers().size());
    assertTrue(store.authenticate("customUser", "secret123").isPresent());

    assertThrows(IllegalArgumentException.class, () -> store.setRepository(null));
  }

  @Test
  void testDisabledUserCannotAuthenticate() {
    HopUserStore store = HopUserStore.getInstance();
    store.upsertUser("disabledUser", "pass", List.of("user"));
    assertTrue(store.authenticate("disabledUser", "pass").isPresent());

    // Disable the user
    HopUser user = store.findUser("disabledUser").orElseThrow();
    user.setEnabled(false);
    store.replaceAllUsers(List.of(user));

    // Must fail authentication even with the correct password
    assertTrue(store.authenticate("disabledUser", "pass").isEmpty());
  }

  @Test
  void testBootstrapAdminBehavior() {
    HopUserStore store = HopUserStore.getInstance();
    assertTrue(store.isEmpty());

    // With allowDefaultAdmin = false and env unset, bootstrap returns false
    boolean createdNoDefault = store.bootstrapAdminIfEmpty(false);
    assertFalse(createdNoDefault);
    assertTrue(store.isEmpty());

    // With allowDefaultAdmin = true, bootstraps admin/admin
    boolean createdDefault = store.bootstrapAdminIfEmpty(true);
    assertTrue(createdDefault);
    assertFalse(store.isEmpty());
    assertTrue(store.authenticate("admin", "admin").isPresent());

    // Subsequent call returns false because store is no longer empty
    assertFalse(store.bootstrapAdminIfEmpty(true));
  }

  @Test
  void testRoleNormalizationAndSecurityContext() {
    HopUserStore store = HopUserStore.getInstance();
    // Test with mixed alias roles and null roles
    HopUser user =
        store.upsertUser("multiRole", "pass", List.of("admin", "hop-operator", "unknownRole"));
    assertEquals("multiRole", user.getUsername());
    assertTrue(user.getRoles().contains("admin"));

    HopSecurityContext ctx = HopUserStore.toSecurityContext(user);
    assertTrue(ctx.allows(Permission.FILE_SAVE));
    assertTrue(ctx.allows(Permission.RUN_EXECUTE));

    // Unrestricted context for null user
    HopSecurityContext unrestricted = HopUserStore.toSecurityContext(null);
    assertTrue(unrestricted.allows(Permission.FILE_SAVE));
  }

  @Test
  void testReplaceAllUsersAndReload() {
    HopUserStore store = HopUserStore.getInstance();
    store.upsertUser("initial", "pass", List.of("user"));
    assertEquals(1, store.listUsers().size());

    String hash1 = PasswordHasher.hash("p1");
    String hash2 = PasswordHasher.hash("p2");
    List<HopUser> batch =
        List.of(
            new HopUser("batch1", hash1, List.of("admin")),
            new HopUser("batch2", hash2, List.of("readonly")));

    store.replaceAllUsers(batch);
    assertEquals(2, store.listUsers().size());
    assertTrue(store.authenticate("batch1", "p1").isPresent());
    assertTrue(store.authenticate("batch2", "p2").isPresent());
    assertTrue(store.findUser("initial").isEmpty());

    // Reload from repository/disk recovers exact users
    store.reload();
    assertEquals(2, store.listUsers().size());
    assertTrue(store.authenticate("batch1", "p1").isPresent());
  }

  @Test
  void testReadExistingUsersJsonFixture() throws Exception {
    String usersJsonPath = HopUserStore.getUsersFilePath();
    FileObject fileObject = HopVfs.getFileObject(usersJsonPath);
    FileObject parentFolder = fileObject.getParent();
    if (parentFolder != null && !parentFolder.exists()) {
      parentFolder.createFolder();
    }

    String fixture =
        """
        {
          "users" : [ {
            "username" : "fixtureAdmin",
            "passwordHash" : "%s",
            "roles" : [ "admin" ],
            "enabled" : true
          } ]
        }
        """
            .formatted(PasswordHasher.hash("fixturePass"));

    try (OutputStream out = HopVfs.getOutputStream(usersJsonPath, false)) {
      out.write(fixture.getBytes(StandardCharsets.UTF_8));
    }

    HopUserStore store = HopUserStore.getInstance();
    store.reload();

    assertFalse(store.isEmpty());
    Optional<HopUser> found = store.findUser("fixtureAdmin");
    assertTrue(found.isPresent());
    assertTrue(store.authenticate("fixtureAdmin", "fixturePass").isPresent());
    assertTrue(store.authenticate("fixtureAdmin", "wrongPass").isEmpty());
  }

  @Test
  void testInjectedRepositoryReloadFailureDoesNotSwitchReference() {
    HopUserStore store = HopUserStore.getInstance();
    IHopUserRepository initialRepo = store.getRepository();
    assertNotNull(initialRepo);

    IHopUserRepository brokenRepo =
        new IHopUserRepository() {
          @Override
          public void reload() {
            throw new org.apache.hop.core.security.repository.AppDbException(
                "Database connection severed");
          }

          @Override
          public List<HopUser> listUsers() {
            return List.of();
          }

          @Override
          public boolean isEmpty() {
            return true;
          }

          @Override
          public Optional<HopUser> findByUsername(String username) {
            return Optional.empty();
          }

          @Override
          public HopUser saveUser(HopUser user) {
            return user;
          }

          @Override
          public void replaceAllUsers(List<HopUser> users) {}

          @Override
          public boolean deleteUser(String username) {
            return false;
          }
        };

    assertThrows(
        org.apache.hop.core.security.repository.AppDbException.class,
        () -> store.setRepository(brokenRepo));

    // Verify repository reference was NOT switched to brokenRepo
    assertEquals(initialRepo, store.getRepository());
  }

  @Test
  void testCorruptedSecurityFilePreventsBootstrapAdminAndDataLoss() throws Exception {
    String usersJsonPath = HopUserStore.getUsersFilePath();
    FileObject fileObject = HopVfs.getFileObject(usersJsonPath);
    FileObject parentFolder = fileObject.getParent();
    if (parentFolder != null && !parentFolder.exists()) {
      parentFolder.createFolder();
    }

    String corruptedContent = "{ corrupted json content without closing braces";
    try (OutputStream out = HopVfs.getOutputStream(usersJsonPath, false)) {
      out.write(corruptedContent.getBytes(StandardCharsets.UTF_8));
    }

    // 1. Initializing HopUserStore on a corrupted file must fail fast with AppDbException
    assertThrows(
        org.apache.hop.core.security.repository.AppDbException.class,
        () -> HopUserStore.getInstance());

    // 2. Verify that an already-instantiated store also fails fast on reload when file is corrupted
    // First initialize a clean store instance
    try (OutputStream out = HopVfs.getOutputStream(usersJsonPath, false)) {
      out.write("{\"users\":[]}".getBytes(StandardCharsets.UTF_8));
    }
    HopUserStore store = HopUserStore.getInstance();

    // Now corrupt the file on disk
    try (OutputStream out = HopVfs.getOutputStream(usersJsonPath, false)) {
      out.write(corruptedContent.getBytes(StandardCharsets.UTF_8));
    }

    // Reloading the corrupted file must fail fast with AppDbException
    assertThrows(
        org.apache.hop.core.security.repository.AppDbException.class, () -> store.reload());

    // 3. Verify the file was NOT overwritten and retains its original bytes
    String remainingContent;
    try (var in = HopVfs.getInputStream(usersJsonPath)) {
      remainingContent = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertEquals(corruptedContent, remainingContent);
  }
}
