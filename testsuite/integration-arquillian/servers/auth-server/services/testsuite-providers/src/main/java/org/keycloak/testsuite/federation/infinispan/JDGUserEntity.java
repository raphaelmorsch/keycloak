/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
 */

package org.keycloak.testsuite.federation.infinispan;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.infinispan.commons.marshall.Externalizer;
import org.infinispan.commons.marshall.MarshallUtil;
import org.infinispan.commons.marshall.SerializeWith;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@SerializeWith(JDGUserEntity.ExternalizerImpl.class)
public class JDGUserEntity {

    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private String password;
    private String totp;
    //Map<String, JDGFederationLinkEntity> federationLinks;

    public JDGUserEntity() {
    }

    private JDGUserEntity(String id, String username, String email, String firstName, String lastName, boolean enabled, String password, String totp) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.enabled = enabled;
        this.password = password;
        this.totp = totp;
        //this.federationLinks = federationLinks;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getTotp() {
        return totp;
    }

    public void setTotp(String totp) {
        this.totp = totp;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JDGUserEntity)) return false;

        JDGUserEntity that = (JDGUserEntity) o;

        if (id != null ? !id.equals(that.id) : that.id != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int hashCode = id != null ? id.hashCode() : 0;
        return hashCode;
    }

    @Override
    public String toString() {
        return String.format("JDGUserEntity [ id=%s, username=%s, email=%s ]", id, username, email);
    }


    public static class ExternalizerImpl implements Externalizer<JDGUserEntity> {

        private static final int VERSION_1 = 1;

        @Override
        public void writeObject(ObjectOutput output, JDGUserEntity value) throws IOException {
            output.writeByte(VERSION_1);

            MarshallUtil.marshallString(value.id, output);
            MarshallUtil.marshallString(value.username, output);
            MarshallUtil.marshallString(value.email, output);
            MarshallUtil.marshallString(value.firstName, output);
            MarshallUtil.marshallString(value.lastName, output);
            output.writeBoolean(value.enabled);
            MarshallUtil.marshallString(value.password, output);
            MarshallUtil.marshallString(value.totp, output);
        }

        @Override
        public JDGUserEntity readObject(ObjectInput input) throws IOException {
            switch (input.readByte()) {
                case VERSION_1:
                    return readObjectVersion1(input);
                default:
                    throw new IOException("Unknown version");
            }
        }

        public JDGUserEntity readObjectVersion1(ObjectInput input) throws IOException {
            return new JDGUserEntity(
                    MarshallUtil.unmarshallString(input), // id
                    MarshallUtil.unmarshallString(input), // username
                    MarshallUtil.unmarshallString(input), // email
                    MarshallUtil.unmarshallString(input), // firstName
                    MarshallUtil.unmarshallString(input), // lastName
                    input.readBoolean(),                  // enabled
                    MarshallUtil.unmarshallString(input), // password
                    MarshallUtil.unmarshallString(input)  // totp
            );
        }
    }
}
