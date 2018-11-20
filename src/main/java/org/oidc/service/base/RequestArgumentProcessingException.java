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

import org.oidc.msg.Error;
import org.oidc.msg.ErrorDetails;

public class RequestArgumentProcessingException extends Exception {
  
  private Error error;

  public RequestArgumentProcessingException(Error err) {
    this.error = err;
  }
  
  public RequestArgumentProcessingException(ErrorDetails details) {
    error = new Error();
    error.getDetails().add(details);
  }
  
  public Error getError() {
    return error;
  }
  
  public String getMessage() {
    return error.getDetails().toString();
  }
}
