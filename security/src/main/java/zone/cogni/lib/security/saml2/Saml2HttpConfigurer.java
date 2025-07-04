package zone.cogni.lib.security.saml2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.common.BasicAuthHandler;
import zone.cogni.lib.security.common.GlobalProperties;
import zone.cogni.lib.security.common.LogoutConfigurer;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class Saml2HttpConfigurer extends SecurityHttpConfigurer<Saml2HttpConfigurer> {
  private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
  private final RoleMappingService roleMappingService;
  private final BasicAuthHandler basicAuthHandler;
  private final GlobalProperties globalProperties;
  private final Saml2Properties saml2Properties;
  private final String contextPath;

  @Override
  public void init(HttpSecurity http) throws Exception {
    log.info("Initializing saml2 security");
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

    http.saml2Login(this::checkAssertionConsumerServiceUrl)
        .with(new LogoutConfigurer(globalProperties.getLogout()), Customizer.withDefaults())
        .addFilterBefore(basicAuthHandler::handleFilter, Saml2WebSsoAuthenticationFilter.class)
        .addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class)
        .addFilterAfter(this::patchAuthenticationObjectFilter, Saml2WebSsoAuthenticationFilter.class);
  }

  private void checkAssertionConsumerServiceUrl(Saml2LoginConfigurer<HttpSecurity> httpSecuritySaml2LoginConfigurer) {
    String assertionConsumerServiceUrl = saml2Properties.getAssertionConsumerServiceUrl();
    if (StringUtils.isBlank(assertionConsumerServiceUrl) || assertionConsumerServiceUrl.endsWith("/{registrationId}")) return;

    RelyingPartyRegistration registrationId = relyingPartyRegistrationRepository.findByRegistrationId(saml2Properties.getRegistrationId());
    httpSecuritySaml2LoginConfigurer.authenticationConverter(new NoRegistrationIdSaml2AuthenticationTokenConverter(registrationId))
                                    .addObjectPostProcessor(new Saml2WebSsoAuthenticationFilterAssertionConsumerServiceSetter(assertionConsumerServiceUrl, contextPath));
  }

  @Override
  public void configure(HttpSecurity builder) {
  }


  private void patchAuthenticationObjectFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();
    if (authentication instanceof Saml2Authentication) {
      DefaultUserDetails samlUserDetails = buildUserDetails((Saml2AuthenticatedPrincipal) authentication.getPrincipal());
      ExtendedSaml2Authentication patchedAuthentication = new ExtendedSaml2Authentication(samlUserDetails, (Saml2Authentication) authentication);
      securityContext.setAuthentication(patchedAuthentication);

      if (BooleanUtils.isTrue(saml2Properties.getLogSamlResponse())) log.info("Received saml response: {}", patchedAuthentication.getSaml2Response());
    }
    else if (null != authentication && !(authentication.getDetails() instanceof DefaultUserDetails)) {
      log.warn("Authentication object is not a security lib one or SAML one: {}", authentication.getClass());
    }

    chain.doFilter(request, response);
  }

  private DefaultUserDetails buildUserDetails(Saml2AuthenticatedPrincipal principal) {
    DefaultUserDetails samlUserDetails = new DefaultUserDetails();
    Saml2Properties.Attributes samlAttributes = saml2Properties.getAttributes();

    String loginId = StringUtils.defaultIfBlank(principal.getFirstAttribute(samlAttributes.getLoginid()), principal.getName());

    samlUserDetails.setAuthorities(getAuthorities(principal))
                   .setLoginId(loginId)
                   .setUsername(loginId)
                   .setEmail(principal.getFirstAttribute(samlAttributes.getEmail()))
                   .setDisplayName(principal.getFirstAttribute(samlAttributes.getDisplayname()))
                   .setFirstName(principal.getFirstAttribute(samlAttributes.getFirstname()))
                   .setLastName(principal.getFirstAttribute(samlAttributes.getLastname()));
    return samlUserDetails;
  }

  private List<GrantedAuthority> getAuthorities(Saml2AuthenticatedPrincipal principal) {
    List<String> samlRoles = principal.getAttribute(saml2Properties.getAttributes().getRoles());
    if (CollectionUtils.isEmpty(samlRoles)) return Collections.emptyList();

    return samlRoles.stream()
                    .map(roleMappingService::getApplicationRoleFor)
                    .filter(Objects::nonNull)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
  }

}
