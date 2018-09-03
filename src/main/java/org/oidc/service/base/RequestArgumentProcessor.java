/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.service.base;

import java.util.Map;

import org.oidc.service.Service;

/**
 * The request argument processors are used when request messages are built for the given
 * {@link Service}. The implementations of this interface can be called prior and after the actual
 * construction of the request message.
 */
public interface RequestArgumentProcessor {

  /**
   * Processes the given request arguments by exploiting the current state of them and the given
   * service.
   * 
   * @param requestArguments
   *          The request arguments to be populated.
   * @param service
   *          The service for which the request message is being constructed.
   * @throws RequestArgumentProcessingException
   *           If anything unexpected happens during processing.
   */
  public void processRequestArguments(Map<String, Object> requestArguments, Service service)
      throws RequestArgumentProcessingException;

}
