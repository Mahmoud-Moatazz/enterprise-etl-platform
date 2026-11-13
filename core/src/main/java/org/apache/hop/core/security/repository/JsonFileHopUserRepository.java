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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.vfs2.FileObject;
import org.apache.hop.core.json.HopJson;
import org.apache.hop.core.logging.LogChannel;
import org.apache.hop.core.security.HopUser;
import org.apache.hop.core.security.HopUserStore;
import org.apache.hop.core.vfs.HopVfs;

/**
 * File-backed user repository implementing {@link IHopUserRepository} using Apache Hop's legacy
 * {@code users.json} format and VFS file access.
 *
 * <p>Preserves exact JSON structure, file locations, case-insensitive username lookups, and
 * concurrency behavior of the stock Apache Hop file-based user store while providing fail-safe
 * corrupted-file protection and safer staged file replacement.
 */
public class JsonFileHopUserRepository implements IHopUserRepository {

  private final Object lock = new Object();
  private final List<HopUser> users = new CopyOnWriteArrayList<>();
  private final Supplier<String> filePathSupplier;

  public JsonFileHopUserRepository() {
    this(HopUserStore::getUsersFilePath);
  }

  public JsonFileHopUserRepository(String filePath) {
    this(() -> filePath);
  }

  public JsonFileHopUserRepository(Supplier<String> filePathSupplier) {
    this.filePathSupplier =
        (filePathSupplier != null) ? filePathSupplier : HopUserStore::getUsersFilePath;
    reload();
  }

  public String getFilePath() {
    return filePathSupplier.get();
  }

  @Override
  public void reload() {
    synchronized (lock) {
      users.clear();
      users.addAll(readFromFile());
    }
  }

  @Override
  public List<HopUser> listUsers() {
    return List.copyOf(users);
  }

  @Override
  public boolean isEmpty() {
    return users.isEmpty();
  }

  @Override
  public Optional<HopUser> findByUsername(String username) {
    if (username == null || username.isBlank()) {
      return Optional.empty();
    }
    String key = username.trim();
    for (HopUser user : users) {
      if (user.getUsername() != null && user.getUsername().equalsIgnoreCase(key)) {
        return Optional.of(user);
      }
    }
    return Optional.empty();
  }

  @Override
  public HopUser saveUser(HopUser user) {
    if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
      throw new IllegalArgumentException("User and non-blank username are required");
    }
    String name = user.getUsername().trim();
    synchronized (lock) {
      HopUser existing = null;
      for (HopUser u : users) {
        if (u.getUsername() != null && u.getUsername().equalsIgnoreCase(name)) {
          existing = u;
          break;
        }
      }
      if (existing != null) {
        existing.setPasswordHash(user.getPasswordHash());
        existing.setRoles(
            user.getRoles() != null ? new ArrayList<>(user.getRoles()) : new ArrayList<>());
        existing.setEnabled(user.isEnabled());
      } else {
        users.add(user);
      }
      writeToFile();
      return findByUsername(name).orElse(user);
    }
  }

  @Override
  public void replaceAllUsers(List<HopUser> newUsers) {
    synchronized (lock) {
      users.clear();
      if (newUsers != null) {
        for (HopUser user : newUsers) {
          if (user != null && user.getUsername() != null && !user.getUsername().isBlank()) {
            users.add(user);
          }
        }
      }
      writeToFile();
    }
  }

  @Override
  public boolean deleteUser(String username) {
    if (username == null || username.isBlank()) {
      return false;
    }
    String key = username.trim();
    synchronized (lock) {
      boolean removed =
          users.removeIf(u -> u.getUsername() != null && u.getUsername().equalsIgnoreCase(key));
      if (removed) {
        writeToFile();
      }
      return removed;
    }
  }

  private List<HopUser> readFromFile() {
    String path = getFilePath();
    boolean exists;
    try {
      exists = HopVfs.fileExists(path);
    } catch (Exception e) {
      throw new AppDbException(
          "Unable to determine existence of Hop security file at '"
              + path
              + "'. Aborting to prevent accidental data loss or unauthorized bootstrap.",
          e);
    }

    if (!exists) {
      // Genuine first-time installation: store is legitimately empty
      return new ArrayList<>();
    }

    try {
      FileObject fileObject = HopVfs.getFileObject(path);
      long size = fileObject.getContent().getSize();
      if (size == 0) {
        throw new AppDbException(
            "Hop security file at '"
                + path
                + "' exists but is empty (0 bytes). Refusing to treat as empty user store to prevent data loss.");
      }
      try (InputStream in = HopVfs.getInputStream(fileObject)) {
        ObjectMapper mapper = HopJson.newMapper();
        UsersFile file = mapper.readValue(in, UsersFile.class);
        if (file == null || file.getUsers() == null) {
          throw new AppDbException(
              "Hop security file at '"
                  + path
                  + "' contains an invalid or empty user file structure.");
        }
        return new ArrayList<>(file.getUsers());
      }
    } catch (AppDbException e) {
      throw e;
    } catch (Exception e) {
      throw new AppDbException(
          "Hop security file exists at '"
              + path
              + "' but could not be read or parsed. Aborting to protect existing credentials from corruption or overwrite.",
          e);
    }
  }

  private void writeToFile() {
    String path = getFilePath();
    FileObject tempFileObject = null;
    try {
      FileObject targetFileObject = HopVfs.getFileObject(path);
      FileObject parentFolder = targetFileObject.getParent();
      if (parentFolder != null && !parentFolder.exists()) {
        parentFolder.createFolder();
      }

      // Step 1: Complete in-memory JSON serialization before opening any file streams
      UsersFile file = new UsersFile();
      file.setUsers(new ArrayList<>(users));
      ObjectMapper mapper = HopJson.newMapper();
      mapper.enable(SerializationFeature.INDENT_OUTPUT);
      byte[] json = mapper.writeValueAsString(file).getBytes(StandardCharsets.UTF_8);

      // Step 2: Write complete contents to a unique temporary staging file in the same directory
      String tempPath = path + "." + UUID.randomUUID() + ".tmp";
      tempFileObject = HopVfs.getFileObject(tempPath);
      try (OutputStream out = HopVfs.getOutputStream(tempFileObject, false)) {
        out.write(json);
        out.flush();
      }

      // Step 3: Replace target file using HopVfs.moveFile (rename with copy+delete fallback)
      HopVfs.moveFile(tempFileObject, targetFileObject);
      tempFileObject = null; // Successfully replaced target

      safeLogBasic("Saved Hop users file to '" + path + "' (" + users.size() + " users)");
    } catch (Exception e) {
      safeLogError("Unable to save Hop users file to '" + path + "'", e);
      throw new AppDbException(
          "Failed to persist Hop users file to '" + path + "'. Target file was preserved.", e);
    } finally {
      if (tempFileObject != null) {
        try {
          if (tempFileObject.exists()) {
            tempFileObject.delete();
          }
        } catch (Exception ignored) {
          // Best effort cleanup of staging file
        }
      }
    }
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

  @Getter
  @Setter
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class UsersFile {
    private List<HopUser> users = new ArrayList<>();
  }
}
