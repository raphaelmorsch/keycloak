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

package org.keycloak.testsuite.federation.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.keycloak.models.LDAPConstants;
import org.keycloak.models.ModelException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LDAPTest {

    private static Map<String, Object> connectionProperties;

    public static void main(String[] args) throws Exception {
        connectionProperties = Collections.unmodifiableMap(createConnectionProperties());
        //InitialLdapContext ctx = new InitialLdapContext(new Hashtable<Object, Object>(connectionProperties), null);
        try {
            runOperation();
        } finally {
        //    ctx.close();
        }
    }

    private static Map<String, Object> createConnectionProperties() {
        HashMap<String, Object> env = new HashMap<String, Object>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "JBOSS3\\jbossqa");
        env.put(Context.SECURITY_CREDENTIALS, "jboss42");
        env.put(Context.PROVIDER_URL, "ldaps://dev156-w2012-x86-64.mw.lab.eng.bos.redhat.com:636");
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        env.put("java.naming.ldap.factory.socket", "javax.net.ssl.SSLSocketFactory");
        env.put("java.naming.ldap.attributes.binary", "objectGUID");

        return env;
    }



    private static void runOperation() {
        updateADPassword("CN=johnkeycloak,OU=People,O=keycloak,DC=JBOSS3,DC=test", "Password123");
    }


    private static void updateADPassword(String userDN, String password) {
        try {
            // Replace the "unicdodePwd" attribute with a new value
            // Password must be both Unicode and a quoted string
            String newQuotedPassword = "\"" + password + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");

            BasicAttribute unicodePwd = new BasicAttribute("unicodePwd", newUnicodePassword);

            List<ModificationItem> modItems = new ArrayList<ModificationItem>();
            modItems.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, unicodePwd));

            modifyAttributes(userDN, modItems.toArray(new ModificationItem[] {}));
        } catch (ModelException me) {
            throw me;
        } catch (Exception e) {
            throw new ModelException(e);
        }
    }

    public static void modifyAttributes(final String dn, final ModificationItem[] mods) {
        try {

            execute(new LdapOperation<Void>() {
                @Override
                public Void execute(LdapContext context) throws NamingException {
                    context.modifyAttributes(dn, mods);
                    return null;
                }
            });
        } catch (NamingException e) {
            throw new ModelException("Could not modify attribute for DN [" + dn + "]", e);
        }
    }

    private static <R> R execute(LdapOperation<R> operation) throws NamingException {
        LdapContext context = null;

        try {
            connectionProperties = Collections.unmodifiableMap(createConnectionProperties());
            context = new InitialLdapContext(new Hashtable<Object, Object>(connectionProperties), null);
            //context.listBindings("OU=People,O=keycloak,DC=JBOSS3,DC=test");
            return operation.execute(context);
        } catch (NamingException ne) {
            throw ne;
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException ne) {
                    throw new RuntimeException("Could not close Ldap context.", ne);
                }
            }
        }
    }

    private interface LdapOperation<R> {
        R execute(LdapContext context) throws NamingException;
    }

    private Set<String> getReturningAttributes(final Collection<String> returningAttributes) {
        Set<String> result = new HashSet<String>();

        result.addAll(returningAttributes);
        result.add("objectGUID");
        result.add(LDAPConstants.OBJECT_CLASS);

        return result;
    }


}
