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

/**
 * Unchecked exception thrown when an operation against the application database or user repository
 * encounters an error (connectivity, SQL execution, pooling, schema migration, or configuration).
 *
 * <p>Propagated unchecked to prevent silent data corruption or fallback to insecure states.
 */
public class AppDbException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public AppDbException(String message) {
    super(message);
  }

  public AppDbException(String message, Throwable cause) {
    super(message, cause);
  }

  public AppDbException(Throwable cause) {
    super(cause);
  }
}
