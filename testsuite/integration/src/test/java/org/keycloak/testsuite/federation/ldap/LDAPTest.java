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
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.directory.api.ldap.model.message.SearchScope;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.ModelException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LDAPTest {

    private static Map<String, Object> connectionProperties;

    private static boolean asAdmin = true;
    private static boolean adControl = true;

    private static String[] MSAD2012 = { "ldaps://dev156-w2012-x86-64.mw.lab.eng.bos.redhat.com:636", "JBOSS3\\jbossqa", "jboss42", "/home/mposolda/tmp/dev156.truststore" };
    private static String[] MSAD2008 = { "ldaps://dev101.mw.lab.eng.bos.redhat.com:636", "JBOSS1\\jbossqa", "jboss42", "/home/mposolda/tmp/dev101.truststore" };
    private static String[] MSAD_SETUP = MSAD2012;

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", MSAD_SETUP[3]);
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
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

        String bindDN = asAdmin ? MSAD_SETUP[1] :"CN=johnkeycloak,OU=People,O=keycloak,DC=JBOSS3,DC=test";
        String bindPAssword = asAdmin ? "jboss42" : "Password124";
        env.put(Context.SECURITY_PRINCIPAL, bindDN);
        env.put(Context.SECURITY_CREDENTIALS, bindPAssword);

        env.put(Context.PROVIDER_URL, MSAD_SETUP[0]);
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        env.put("java.naming.ldap.factory.socket", "javax.net.ssl.SSLSocketFactory");
        env.put("java.naming.ldap.attributes.binary", "objectGUID");

        return env;
    }



    private static void runOperation() throws NamingException {
//        if (asAdmin) {
//            updatePasswordHistoryPolicy(1);
//            updateADPassword("CN=johnkeycloak,OU=People,O=keycloak,DC=JBOSS3,DC=test", "Password373");
//            updatePasswordHistoryPolicy(86400000);
//        } else {
//            updateADPasswordOnUserBehalf("CN=johnkeycloak,OU=People,O=keycloak,DC=JBOSS3,DC=test", "Password124", "Password128");
//        }

//        List<SearchResult> res = search("OU=People,O=keycloak,DC=JBOSS3,DC=test", "(CN=johnkeycloak)", getReturningAttributes(new HashSet<>()), SearchControls.ONELEVEL_SCOPE);
//        InitialLdapContext ctx = new InitialLdapContext();
//        for (SearchResult sr : res) {
//            System.out.println(sr.getName() + " " + sr.getNameInNamespace() + " " + sr.getAttributes());
//        }

        rename(null, "CN=johnkeycloak2,OU=People,O=keycloak,DC=JBOSS3,DC=test", "CN=johnkeycloak234-foo,OU=People,O=keycloak,DC=JBOSS3,DC=test");

    }


    public static void rename(final String baseDN, String previousRDN, String newRDN) throws NamingException {
//        final List<SearchResult> result = new ArrayList<SearchResult>();
//        final SearchControls cons = getSearchControls(returningAttributes, searchScope);

        try {
            execute(new LdapOperation<Boolean>() {
                @Override
                public Boolean execute(LdapContext context) throws NamingException {
                    context.rename(previousRDN, newRDN);
                    return true;
                }
            });
        } catch (NamingException e) {
            e.printStackTrace();
            throw e;
        }
    }


    private static void updatePasswordHistoryPolicy(long passwordMinAgeMs) {
        try {

            String passwordMinPage = String.valueOf(passwordMinAgeMs * -10000);
            BasicAttribute unicodePwd = new BasicAttribute("minPwdAge", passwordMinPage);

            List<ModificationItem> modItems = new ArrayList<ModificationItem>();
            modItems.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, unicodePwd));
            modifyAttributes("DC=JBOSS3,DC=test", modItems.toArray(new ModificationItem[] {}));
        } catch (ModelException me) {
            throw me;
        } catch (Exception e) {
            throw new ModelException(e);
        }
    }


    private static void updateADPassword(String userDN, String password) {
        try {
            // Replace the "unicdodePwd" attribute with a new value
            // Password must be both Unicode and a quoted string
            String newQuotedPassword = "\"" + password + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");

            final byte[][] multiBA = new byte[][] { newUnicodePassword };

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

    private static void updateADPasswordOnUserBehalf(String userDN, String oldPassword, String newPassword) {
        try {
            // Replace the "unicdodePwd" attribute with a new value
            // Password must be both Unicode and a quoted string
            String oldQuotedPassword = "\"" + oldPassword + "\"";
            byte[] oldUnicodePassword = oldQuotedPassword.getBytes("UTF-16LE");

            String newQuotedPassword = "\"" + newPassword + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");

            BasicAttribute oldUnicodePwd = new BasicAttribute("unicodePwd", oldUnicodePassword);
            BasicAttribute newUnicodePwd = new BasicAttribute("unicodePwd", newUnicodePassword);

            List<ModificationItem> modItems = new ArrayList<ModificationItem>();
            modItems.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, oldUnicodePwd));
            modItems.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, newUnicodePwd));

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
                    if (adControl) {
                        final byte[] controlData = {48, (byte) 132, 0, 0, 0, 3, 2, 1, 1};

                        String LDAP_SERVER_POLICY_HINTS_OID = "1.2.840.113556.1.4.2239";
                        String LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID = "1.2.840.113556.1.4.2066";

                        BasicControl control = new BasicControl(LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID, true, controlData);
                        BasicControl[] controls = new BasicControl[] { control };
                        context.setRequestControls(controls);
                    }

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



    public static List<SearchResult> search(final String baseDN, final String filter, Collection<String> returningAttributes, int searchScope) throws NamingException {
        final List<SearchResult> result = new ArrayList<SearchResult>();
        final SearchControls cons = getSearchControls(returningAttributes, searchScope);

        try {
            return execute(new LdapOperation<List<SearchResult>>() {
                @Override
                public List<SearchResult> execute(LdapContext context) throws NamingException {
                    NamingEnumeration<SearchResult> search = context.search(baseDN, filter, cons);

                    while (search.hasMoreElements()) {
                        result.add(search.nextElement());
                    }

                    search.close();

                    return result;
                }
            });
        } catch (NamingException e) {
            e.printStackTrace();
            throw e;
        }
    }

    private static SearchControls getSearchControls(Collection<String> returningAttributes, int searchScope) {
        final SearchControls cons = new SearchControls();

        cons.setSearchScope(searchScope);
        cons.setReturningObjFlag(false);

        returningAttributes = getReturningAttributes(returningAttributes);

        cons.setReturningAttributes(returningAttributes.toArray(new String[returningAttributes.size()]));
        return cons;
    }

    private static Set<String> getReturningAttributes(final Collection<String> returningAttributes) {
        Set<String> result = new HashSet<String>();

        result.addAll(returningAttributes);
        result.add("objectGUID");
        result.add(LDAPConstants.OBJECT_CLASS);
        result.add(LDAPConstants.CN);
        result.add(LDAPConstants.GIVENNAME);
        result.add(LDAPConstants.SN);
        result.add(LDAPConstants.SAM_ACCOUNT_NAME);

        return result;
    }


}
