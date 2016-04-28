/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.util.cli;

import java.util.List;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.predicate.PredicatesHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
import io.undertow.util.HeaderValues;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class UndertowPredicateSample {

    public static void main(String[] args) {
        HttpHandler httpHandler = new HttpHandler() {
            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                String s2 = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                exchange.getResponseSender().send("<html><body><h1>Hello World</h1></body></html>");
            }
        };



        //String predicate = "regex(value=%{i, X-Protocol-For}, pattern='\\(.*\\),\\(.*\\)') -> set[attribute='%{i,X-Protocol-For}', value='${1}']";
        //String predicate2 = "regex(value=%{i, X-Protocol-For}, pattern='\\(.*\\),\\(.*\\)')";

        String predicate3 = "regex(value='%{i,X-Forwarded-For}', pattern='(.*),(.*)') -> set(attribute='%{i,X-Forwarded-For}', value='${2}')";
        //String predicate4 = "regex(value='%{o, X-Protocol-For}', pattern='(.*),(.*)') -> set(attribute='%{o,Location}', value='/b${1}')";
        List<PredicatedHandler> preds = PredicatedHandlersParser.parse(predicate3,
                UndertowPredicateSample.class.getClassLoader());
        PredicatesHandler predicatesHandler = Handlers.predicates(preds, httpHandler);


        Undertow server = Undertow.builder()
                .addHttpListener(8080, "node1")
                .setHandler(predicatesHandler).build();
        server.start();
        System.out.println("Foo");
    }
}
