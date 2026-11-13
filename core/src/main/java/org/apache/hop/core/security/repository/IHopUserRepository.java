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

import java.util.List;
import java.util.Optional;
import org.apache.hop.core.security.HopUser;

/**
 * Persistence abstraction for Hop Web users.
 *
 * <p>Implementations manage user entity storage (e.g. JSON file or PostgreSQL database).
 * Authentication, credential verification, and password hashing responsibilities remain outside
 * this repository in {@link org.apache.hop.core.security.HopUserStore}.
 */
public interface IHopUserRepository {

  /**
   * Reload users from persistent storage into memory or refresh local cache.
   *
   * @throws AppDbException if reloading fails due to a storage error
   */
  void reload();

  /**
   * List all stored users.
   *
   * @return snapshot or unmodifiable list of users
   * @throws AppDbException if retrieval fails due to a storage error
   */
  List<HopUser> listUsers();

  /**
   * Check whether the user repository is empty.
   *
   * @return true if no users exist in storage
   * @throws AppDbException if query fails due to a storage error
   */
  boolean isEmpty();

  /**
   * Lookup a user by username (case-insensitive).
   *
   * @param username the username to look up
   * @return Optional containing the user if found, or empty if absent
   * @throws AppDbException if query fails due to a storage error
   */
  Optional<HopUser> findByUsername(String username);

  /**
   * Save or update a user entity (with password hash already computed).
   *
   * @param user the user to persist
   * @return the persisted user entity
   * @throws AppDbException if persistence fails due to a storage error
   */
  HopUser saveUser(HopUser user);

  /**
   * Atomically replace the entire user collection with the provided list.
   *
   * @param users complete user list to persist
   * @throws AppDbException if batch replacement fails due to a storage error
   */
  void replaceAllUsers(List<HopUser> users);

  /**
   * Delete a user by username (case-insensitive).
   *
   * @param username the username of the user to delete
   * @return true if the user existed and was deleted, false otherwise
   * @throws AppDbException if deletion fails due to a storage error
   */
  boolean deleteUser(String username);
}
