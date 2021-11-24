/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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
 *
 */

package org.keycloak.representations.idm;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientTypeRepresentation {

    @JsonProperty("client-type-provider")
    private String clientTypeProvider;

    @JsonProperty("config")
    private Map<String, PropertyConfig> config;


    public static class PropertyConfig<T> {

        @JsonProperty("applicable")
        private Boolean applicable;

        @JsonProperty("read-only")
        private Boolean readOnly;

        @JsonProperty("default-value")
        private T defaultValue;

        public Boolean getApplicable() {
            return applicable;
        }

        public void setApplicable(Boolean applicable) {
            this.applicable = applicable;
        }

        public Boolean getReadOnly() {
            return readOnly;
        }

        public void setReadOnly(Boolean readOnly) {
            this.readOnly = readOnly;
        }

        public T getDefaultValue() {
            return defaultValue;
        }

        public void setDefaultValue(T defaultValue) {
            this.defaultValue = defaultValue;
        }
    }
}
