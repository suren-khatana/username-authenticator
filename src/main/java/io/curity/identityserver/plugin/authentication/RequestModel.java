/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.authentication;

import jakarta.validation.Valid;
import org.hibernate.validator.constraints.NotBlank;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.web.Request;

import java.util.Optional;

public final class RequestModel {

    /**
     * If the request is not a POST request, this variable can be set to null.
     * Otherwise, it must not be null and it gets validated by the server using Hibernate annotations.
     */
    @Nullable
    @Valid
    private final Post _postRequestModel;

    RequestModel(Request request) {
        _postRequestModel = request.isPostRequest() ? new Post(request) : null;
    }

    Post getPostRequestModel() {
        return Optional.ofNullable(_postRequestModel).orElseThrow(() ->
                new RuntimeException("Post RequestModel does not exist"));
    }

    static class Post {
        static final String USERNAME_PARAM = "username";


        @NotBlank(message = "validation.error.accountId.required")
        private final String _userName;

        Post(Request request) {
            _userName = request.getFormParameterValueOrError(USERNAME_PARAM);

        }

        String getUserName() {
            // the request model was already validated if this getter ever gets called, so this is safe
            return _userName;
        }


    }
}