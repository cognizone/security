package zone.cogni.lib.security.saml2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.common.GlobalProperties;
import zone.cogni.lib.security.common.LogoutConfigurer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
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

  @Override
  public void init(HttpSecurity http) throws Exception {
    log.info("Initializing saml2 security");
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

    http
            .saml2Login().and()
            .apply(new LogoutConfigurer(globalProperties.getLogout())).and()
            .addFilterBefore(this::basicAuthFilter, Saml2WebSsoAuthenticationFilter.class)
            .addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class)
            .addFilterAfter(this::patchAuthenticationObjectFilter, Saml2WebSsoAuthenticationFilter.class);
  }

  @Override
  public void configure(HttpSecurity http) {
  }

  private void basicAuthFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
    basicAuthHandler.handle((HttpServletRequest) request);
    chain.doFilter(request, response);
  }

  private void patchAuthenticationObjectFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();
    if (authentication instanceof Saml2Authentication) {
      List<GrantedAuthority> authorities = getAuthorities((Saml2AuthenticatedPrincipal) authentication.getPrincipal());
      ExtendedSaml2Authentication patchedAuthentication = new ExtendedSaml2Authentication(authorities, (Saml2Authentication) authentication);
      securityContext.setAuthentication(patchedAuthentication);

      if (BooleanUtils.isTrue(saml2Properties.getLogSamlResponse())) log.info("Received saml response: {}", patchedAuthentication.getSaml2Response());
    }
    else if (null != authentication && !(authentication instanceof ExtendedSaml2Authentication)) {
      log.warn("Authentication object is not instanceof (Extended)Saml2Authentication: {}", authentication.getClass());
    }

    chain.doFilter(request, response);
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