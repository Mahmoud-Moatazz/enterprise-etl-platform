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

package org.apache.hop.core.security.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.hop.core.security.HopUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JsonFileHopUserRepositoryTest {

  @TempDir Path tempDir;

  private Path usersFile;
  private JsonFileHopUserRepository repository;

  @BeforeEach
  void setUp() {
    usersFile = tempDir.resolve("security").resolve("users.json");
    repository = new JsonFileHopUserRepository(usersFile.toAbsolutePath().toString());
  }

  @Test
  void testInitialStateIsEmpty() {
    assertTrue(repository.isEmpty());
    assertEquals(0, repository.listUsers().size());
    assertTrue(repository.findByUsername("any").isEmpty());
    assertTrue(repository.findByUsername(null).isEmpty());
    assertTrue(repository.findByUsername("   ").isEmpty());
  }

  @Test
  void testSaveAndFindByUsernameCaseInsensitive() {
    HopUser user = new HopUser("Alice", "hash123", List.of("admin", "user"));
    HopUser saved = repository.saveUser(user);

    assertNotNull(saved);
    assertEquals("Alice", saved.getUsername());
    assertEquals("hash123", saved.getPasswordHash());
    assertFalse(repository.isEmpty());
    assertEquals(1, repository.listUsers().size());

    // Exact match
    Optional<HopUser> foundExact = repository.findByUsername("Alice");
    assertTrue(foundExact.isPresent());
    assertEquals("Alice", foundExact.get().getUsername());

    // Lowercase match
    Optional<HopUser> foundLower = repository.findByUsername("alice");
    assertTrue(foundLower.isPresent());
    assertEquals("Alice", foundLower.get().getUsername());

    // Uppercase match
    Optional<HopUser> foundUpper = repository.findByUsername("ALICE");
    assertTrue(foundUpper.isPresent());
    assertEquals("Alice", foundUpper.get().getUsername());

    // Mixed case match
    Optional<HopUser> foundMixed = repository.findByUsername("aLiCe");
    assertTrue(foundMixed.isPresent());
  }

  @Test
  void testUpdateExistingUserPreservesSingleEntry() {
    repository.saveUser(new HopUser("bob", "hash1", List.of("readonly")));
    assertEquals(1, repository.listUsers().size());

    HopUser update = new HopUser("BOB", "hashUpdated", List.of("admin"));
    update.setEnabled(false);
    repository.saveUser(update);

    assertEquals(1, repository.listUsers().size());
    HopUser stored = repository.findByUsername("bob").orElseThrow();
    assertEquals("hashUpdated", stored.getPasswordHash());
    assertEquals(List.of("admin"), stored.getRoles());
    assertFalse(stored.isEnabled());
  }

  @Test
  void testDeleteUserCaseInsensitive() {
    repository.saveUser(new HopUser("Charlie", "hashC", List.of("operator")));
    assertFalse(repository.isEmpty());

    // Delete non-existent user returns false
    assertFalse(repository.deleteUser("nonexistent"));
    assertFalse(repository.deleteUser(null));
    assertFalse(repository.deleteUser("  "));

    // Delete existing user with different case returns true
    assertTrue(repository.deleteUser("charlie"));
    assertTrue(repository.isEmpty());
    assertTrue(repository.findByUsername("Charlie").isEmpty());
  }

  @Test
  void testPersistenceAndReload() {
    repository.saveUser(new HopUser("persistedUser", "hashPersist", List.of("user")));
    assertTrue(Files.exists(usersFile));

    // Create a new instance pointing to the same file
    JsonFileHopUserRepository secondRepo =
        new JsonFileHopUserRepository(usersFile.toAbsolutePath().toString());
    assertFalse(secondRepo.isEmpty());
    assertEquals(1, secondRepo.listUsers().size());

    HopUser loaded = secondRepo.findByUsername("persistedUser").orElseThrow();
    assertEquals("hashPersist", loaded.getPasswordHash());
    assertEquals(List.of("user"), loaded.getRoles());
    assertTrue(loaded.isEnabled());
  }

  @Test
  void testReplaceAllUsers() {
    repository.saveUser(new HopUser("u1", "h1", List.of("user")));
    repository.saveUser(new HopUser("u2", "h2", List.of("user")));
    assertEquals(2, repository.listUsers().size());

    List<HopUser> replacement =
        List.of(
            new HopUser("admin1", "adminHash", List.of("admin")),
            new HopUser("admin2", "adminHash2", List.of("admin")));

    repository.replaceAllUsers(replacement);
    assertEquals(2, repository.listUsers().size());
    assertTrue(repository.findByUsername("u1").isEmpty());
    assertTrue(repository.findByUsername("u2").isEmpty());
    assertTrue(repository.findByUsername("admin1").isPresent());
    assertTrue(repository.findByUsername("admin2").isPresent());
  }

  @Test
  void testReadExistingLegacyJsonFileFormat() throws Exception {
    Files.createDirectories(usersFile.getParent());
    String legacyJson =
        """
        {
          "users" : [ {
            "username" : "legacyAdmin",
            "passwordHash" : "pbkdf2:sha256:10000$demo$hashVal",
            "roles" : [ "admin", "hop-admin" ],
            "enabled" : true
          }, {
            "username" : "legacyViewer",
            "passwordHash" : "pbkdf2:sha256:10000$demo$hashVal2",
            "roles" : [ "readonly" ],
            "enabled" : false
          } ]
        }
        """;
    Files.writeString(usersFile, legacyJson);

    repository.reload();

    assertEquals(2, repository.listUsers().size());

    HopUser admin = repository.findByUsername("legacyAdmin").orElseThrow();
    assertEquals("legacyAdmin", admin.getUsername());
    assertEquals("pbkdf2:sha256:10000$demo$hashVal", admin.getPasswordHash());
    assertEquals(List.of("admin", "hop-admin"), admin.getRoles());
    assertTrue(admin.isEnabled());

    HopUser viewer = repository.findByUsername("legacyViewer").orElseThrow();
    assertEquals("legacyViewer", viewer.getUsername());
    assertFalse(viewer.isEnabled());
  }

  @Test
  void testSaveUserValidation() {
    assertThrows(IllegalArgumentException.class, () -> repository.saveUser(null));
    assertThrows(IllegalArgumentException.class, () -> repository.saveUser(new HopUser()));
    assertThrows(
        IllegalArgumentException.class,
        () -> repository.saveUser(new HopUser("   ", "hash", List.of())));
  }

  @Test
  void testZeroByteFileThrowsAppDbException() throws Exception {
    Files.createDirectories(usersFile.getParent());
    Files.createFile(usersFile);
    assertEquals(0, Files.size(usersFile));

    AppDbException ex = assertThrows(AppDbException.class, () -> repository.reload());
    assertTrue(ex.getMessage().contains("0 bytes"));
  }

  @Test
  void testMalformedJsonFileThrowsAppDbException() throws Exception {
    Files.createDirectories(usersFile.getParent());
    Files.writeString(usersFile, "{ \"users\": [ { broken-json-syntax }");

    AppDbException ex = assertThrows(AppDbException.class, () -> repository.reload());
    assertTrue(ex.getMessage().contains("could not be read or parsed"));
    assertNotNull(ex.getCause());
  }

  @Test
  void testStaleTemporaryFilesDoNotAffectRepository() throws Exception {
    Files.createDirectories(usersFile.getParent());
    Path staleTemp = usersFile.getParent().resolve("users.json.12345.tmp");
    Files.writeString(staleTemp, "corrupted leftover content");

    repository.saveUser(new HopUser("validUser", "hashVal", List.of("admin")));

    // Primary users.json is valid and accessible
    assertTrue(Files.exists(usersFile));
    assertEquals(1, repository.listUsers().size());
    assertTrue(repository.findByUsername("validUser").isPresent());

    // Stale temp file does not interfere with reloading
    repository.reload();
    assertEquals(1, repository.listUsers().size());
  }

  @Test
  void testConcurrentWritesDoNotCorruptJson() throws Exception {
    int threadCount = 8;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(threadCount);
    List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());

    for (int i = 0; i < threadCount; i++) {
      final int idx = i;
      executor.submit(
          () -> {
            try {
              startLatch.await();
              repository.saveUser(
                  new HopUser("concurrentUser_" + idx, "hash_" + idx, List.of("user")));
            } catch (Throwable t) {
              errors.add(t);
            } finally {
              doneLatch.countDown();
            }
          });
    }

    startLatch.countDown();
    assertTrue(doneLatch.await(10, TimeUnit.SECONDS));
    executor.shutdown();

    assertTrue(errors.isEmpty(), "Concurrent writes produced errors: " + errors);
    assertEquals(threadCount, repository.listUsers().size());

    // Verify written file on disk parses cleanly
    JsonFileHopUserRepository freshRepo =
        new JsonFileHopUserRepository(usersFile.toAbsolutePath().toString());
    assertEquals(threadCount, freshRepo.listUsers().size());
  }
}
