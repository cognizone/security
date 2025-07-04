package zone.cogni.lib.security.saml2;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import zone.cogni.lib.security.common.BasicAuthHandler;
import zone.cogni.lib.security.common.PermissionGlobalMethodSecurityConfiguration;
import zone.cogni.lib.security.common.ResourceHelper;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType.SIGNING;

@Configuration
@Slf4j
public class Saml2Configuration extends PermissionGlobalMethodSecurityConfiguration {
  private static final String defaultEntityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
  private static final String defaultAssertionConsumerServiceLocation = "{baseUrl}/login/saml2/sso/{registrationId}";

  @Bean
  public Saml2HttpConfigurer saml2HttpConfigurer(@Value("${server.servlet.context-path:}") String contextPath) {
    if (StringUtils.isBlank(contextPath)) {
      contextPath = "/";
    }
    else {
      contextPath = StringUtils.prependIfMissing(contextPath, "/");
      contextPath = StringUtils.appendIfMissing(contextPath, "/");
    }
    return new Saml2HttpConfigurer(relyingPartyRegistrationRepository(), roleMappingService(), basicAuthHandler(), globalProperties(), saml2Properties(), contextPath);
  }

  @Bean
  public RoleMappingService roleMappingService() {
    return new RoleMappingService(saml2Properties());
  }

  @Bean
  public BasicAuthHandler basicAuthHandler() {
    return new BasicAuthHandler(saml2Properties().getBasicAuthUsers());
  }

  @Bean
  public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
    Saml2Properties properties = saml2Properties();
    log.info("Init RelyingPartyRegistration with {}", properties);

    Saml2X509Credential signingCertificate = getSigningCertificate(saml2Properties().getSigningKeyStore());
    RelyingPartyRegistration.Builder rprBuilder = RelyingPartyRegistrations.fromMetadataLocation(properties.getIdpUrl())
                                                                           .signingX509Credentials(coll -> coll.add(signingCertificate))
                                                                           .registrationId(properties.getRegistrationId());
    String baseUrl = StringUtils.defaultIfBlank(properties.getBaseUrl(), "{baseUrl}");
    String entityIdTemplate = StringUtils.firstNonBlank(properties.getEntityId(), defaultEntityId);
    String assertionConsumerServiceUrlTemplate = StringUtils.firstNonBlank(properties.getAssertionConsumerServiceUrl(), defaultAssertionConsumerServiceLocation);
    log.info("Using entityIdTemplate: {}", entityIdTemplate);
    log.info("Using assertionConsumerServiceUrlTemplate: {}", assertionConsumerServiceUrlTemplate);
    rprBuilder.entityId(entityIdTemplate.replace("{baseUrl}", baseUrl))
              .assertionConsumerServiceLocation(assertionConsumerServiceUrlTemplate.replace("{baseUrl}", baseUrl));

    if (StringUtils.isNotBlank(globalProperties().getLogout().getUrl())) {
      String logoutUrl = baseUrl + "/saml/singleLogout";
      log.info("Setting logout-url in RelyingPartyRegistration to {}", logoutUrl);
      rprBuilder.singleLogoutServiceLocation(logoutUrl);
      rprBuilder.singleLogoutServiceResponseLocation(logoutUrl);
    }

    return new InMemoryRelyingPartyRegistrationRepository(rprBuilder.build());
  }

  @Bean
  @ConfigurationProperties(prefix = "cognizone.security.saml2")
  public Saml2Properties saml2Properties() {
    return new Saml2Properties();
  }

  private Saml2X509Credential getSigningCertificate(Saml2Properties.SigningKeys signingKeyStore) {
    if (signingKeyStore.getType() == Saml2Properties.KeyStoreType.JKS) return loadJksSigningCertificate(signingKeyStore);
    throw new RuntimeException("Unknown type of keystore: " + signingKeyStore.getType());
  }

  private Saml2X509Credential loadJksSigningCertificate(Saml2Properties.SigningKeys signingKeyStore) {
    Resource storeResource = ResourceHelper.getResourceFromUrl(signingKeyStore.getStoreUrl());
    try (InputStream storeInputStream = storeResource.getInputStream()) {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(storeInputStream, signingKeyStore.getKeystorePassword().toCharArray());

      KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(signingKeyStore.getAlias(), new KeyStore.PasswordProtection(signingKeyStore.getCertificatePassword().toCharArray()));
      PrivateKey privateKey = privateKeyEntry.getPrivateKey();
      Certificate certificate = privateKeyEntry.getCertificate();
      return new Saml2X509Credential(privateKey, (X509Certificate) certificate, SIGNING);
    }
    catch (Exception e) {
      throw new RuntimeException("Failed to load certificate for signing", e);
    }
  }
}
