/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.cluster.infinispan.test;

import org.infinispan.protostream.annotations.ProtoFactory;
import org.infinispan.protostream.annotations.ProtoField;

public class Book {
    @ProtoField(number = 1)
    final String title;

    @ProtoField(number = 2)
    final String description;

    @ProtoField(number = 3, defaultValue = "0")
    final int publicationYear;

    //@ProtoField(number = 4, collectionImplementation = ArrayList.class)
    //final List<Author> authors;

    @ProtoFactory
    public Book(String title, String description, int publicationYear) {
        this.title = title;
        this.description = description;
        this.publicationYear = publicationYear;
        //this.authors = authors;
    }
    // public Getter methods omitted for brevity


    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public int getPublicationYear() {
        return publicationYear;
    }

    @Override
    public String toString() {
        return "BOOK [ " + title + " ]";
    }
}
