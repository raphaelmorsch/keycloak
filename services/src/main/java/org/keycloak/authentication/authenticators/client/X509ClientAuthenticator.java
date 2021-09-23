package org.keycloak.authentication.authenticators.client;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import javax.security.auth.x500.X500Principal;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class X509ClientAuthenticator extends AbstractClientAuthenticator {

    public static final String PROVIDER_ID = "client-x509";
    public static final String ATTR_PREFIX = "x509";
    public static final String ATTR_SUBJECT_DN = ATTR_PREFIX + ".subjectdn";

    public static final String ATTR_SUBJECT_DN_FORMAT = ATTR_PREFIX + ".subjectdn.format";

    // Custom OIDs defined in the OpenBanking Brasil - https://openbanking-brasil.github.io/specs-seguranca/open-banking-brasil-certificate-standards-1_ID1.html#name-client-certificate
    // These are not recognized by default in RFC1779 or RFC2253 and hence not read in the java by default
    private static final Map<String, String> CUSTOM_OIDS = new HashMap<>();
    static {
        CUSTOM_OIDS.put("2.5.4.5", "serialNumber".toUpperCase());
        CUSTOM_OIDS.put("2.5.4.15", "businessCategory".toUpperCase());
        CUSTOM_OIDS.put("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName".toUpperCase());
    }

    protected static ServicesLogger logger = ServicesLogger.LOGGER;


    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {

        X509ClientCertificateLookup provider = context.getSession().getProvider(X509ClientCertificateLookup.class);
        if (provider == null) {
            logger.errorv("\"{0}\" Spi is not available, did you forget to update the configuration?",
                    X509ClientCertificateLookup.class);
            return;
        }

        X509Certificate[] certs = null;
        ClientModel client = null;
        try {
            certs = provider.getCertificateChain(context.getHttpRequest());
            String client_id = null;
            MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
            boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

            MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters() : null;
            MultivaluedMap<String, String> queryParams = context.getSession().getContext().getUri().getQueryParameters();

            if (formData != null) {
                client_id = formData.getFirst(OAuth2Constants.CLIENT_ID);
            }

            if (client_id == null && queryParams != null) {
                client_id = queryParams.getFirst(OAuth2Constants.CLIENT_ID);
            }

            if (client_id == null) {
                client_id = context.getSession().getAttribute("client_id", String.class);
            }

            if (client_id == null) {
                Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Missing client_id parameter");
                context.challenge(challengeResponse);
                return;
            }

            client = context.getRealm().getClientByClientId(client_id);
            if (client == null) {
                context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
                return;
            }
            context.getEvent().client(client_id);
            context.setClient(client);

            if (!client.isEnabled()) {
                context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
                return;
            }
        } catch (GeneralSecurityException e) {
            logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
            context.attempted();
            return;
        }

        if (certs == null || certs.length == 0) {
            // No x509 client cert, fall through and
            // continue processing the rest of the authentication flow
            logger.debug("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
            context.attempted();
            return;
        }

        OIDCAdvancedConfigWrapper clientCfg = OIDCAdvancedConfigWrapper.fromClientModel(client);
        String subjectDNRegexp = client.getAttribute(ATTR_SUBJECT_DN);
        if (subjectDNRegexp == null || subjectDNRegexp.length() == 0) {
            logger.errorf("[X509ClientCertificateAuthenticator:authenticate] " + ATTR_SUBJECT_DN + " is null or empty");
            context.attempted();
            return;
        }
        Pattern subjectDNPattern = Pattern.compile(subjectDNRegexp);

        Optional<String> matchedCertificate = Arrays.stream(certs)
              .map(certificate -> getSubjectDNFromCertificate(certificate, clientCfg))
              .filter(subjectdn -> subjectDNPattern.matcher(subjectdn).matches())
              .findFirst();

        if (!matchedCertificate.isPresent()) {
            // We do quite expensive operation here, so better check the logging level beforehand.
            if (logger.isDebugEnabled()) {
                logger.debug("[X509ClientCertificateAuthenticator:authenticate] Couldn't match any certificate for pattern '" + subjectDNRegexp + "' and Subject DN Format '" + getRequestedSubjectDNFormat(clientCfg) + "'.");
                logger.debug("[X509ClientCertificateAuthenticator:authenticate] Available SubjectDNs in the requested format: " +
                      Arrays.stream(certs)
                            .map(cert -> getSubjectDNFromCertificate(cert, clientCfg))
                            .collect(Collectors.toList()));
            }
            context.attempted();
            return;
        } else {
            logger.debug("[X509ClientCertificateAuthenticator:authenticate] Matched " + matchedCertificate.get() + " certificate.");
        }

        context.success();
    }

    protected String getSubjectDNFromCertificate(X509Certificate x509Certificate, OIDCAdvancedConfigWrapper clientCfg) {
        SubjectDNFormat format = getRequestedSubjectDNFormat(clientCfg);
        return format.getSubjectDn(x509Certificate);
    }

    private SubjectDNFormat getRequestedSubjectDNFormat(OIDCAdvancedConfigWrapper clientCfg) {
        String formatCfg = clientCfg.getTlsClientAuthSubjectDnFormat();

        // Defaults to LEGACY format due the backwards compatibility
        return formatCfg == null ? SubjectDNFormat.LEGACY : Enum.valueOf(SubjectDNFormat.class, formatCfg);
    }

    public String getDisplayType() {
        return "X509 Certificate";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return Collections.emptyMap();
    }

   @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.TLS_CLIENT_AUTH);
            return results;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public String getHelpText() {
        return "Validates client based on a X509 Certificate";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    public enum SubjectDNFormat {
        RFC2253(x509Certificate -> x509Certificate.getSubjectX500Principal().getName(X500Principal.RFC2253, CUSTOM_OIDS)),
        RFC1779(x509Certificate -> x509Certificate.getSubjectX500Principal().getName(X500Principal.RFC1779, CUSTOM_OIDS)),
        CANONICAL(x509Certificate -> x509Certificate.getSubjectX500Principal().getName(X500Principal.CANONICAL)),
        LEGACY(x509Certificate -> x509Certificate.getSubjectDN().getName());

        private final Function<X509Certificate, String> formatter;

        SubjectDNFormat(Function<X509Certificate, String> formatter) {
            this.formatter = formatter;
        }

        protected String getSubjectDn(X509Certificate cert) {
            return formatter.apply(cert);
        }
    }
}
