package zone.cogni.lib.security.basicauth;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.common.BasicAuthUser;
import zone.cogni.lib.security.common.GlobalProperties;
import zone.cogni.lib.security.common.LogoutConfigurer;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class BasicAuthHttpConfigurer extends SecurityHttpConfigurer<BasicAuthHttpConfigurer> {
  private static final String[] emptyStringArray = new String[0];
  private static final String defaultRealmName = "Who are you?";

  private final GlobalProperties globalProperties;
  private final BasicAuthProperties basicAuthProperties;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;
  private Map<String, DefaultUserDetails> userInfo;

  @PostConstruct
  @SneakyThrows
  private void init() {
    log.info("Initializing basic-auth security");
    InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer = authenticationManagerBuilder.inMemoryAuthentication();
    userInfo = basicAuthProperties.getUsers()
                                  .entrySet()
                                  .stream()
                                  .peek(entry -> addUser(configurer, entry.getKey(), entry.getValue()))
                                  .map(entry -> convertToUserDetails(entry.getKey(), entry.getValue()))
                                  .collect(Collectors.toMap(DefaultUserDetails::getUsername, Function.identity()));
  }

  private void addUser(InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer, String userName, BasicAuthUser user) {
    configurer.withUser(userName)
              .password(user.getPassword())
              .authorities(user.getRoles().toArray(emptyStringArray));
  }

  private DefaultUserDetails convertToUserDetails(String username, BasicAuthUser user) {
    return new DefaultUserDetails()
            .setAuthorities(user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()))
            .setUsername(username)
            .setLoginId(username)
            .setDisplayName(user.getDisplayName())
            .setEmail(user.getEmail());
  }

  @Override
  @SneakyThrows
  public void init(HttpSecurity http) {
    http.httpBasic(this::httpBasicConfigurer)
        .with(new LogoutConfigurer(globalProperties.getLogout()), Customizer.withDefaults())
        .addFilterAfter(this::patchAuthenticationObjectFilter, BasicAuthenticationFilter.class);
  }

  private void httpBasicConfigurer(HttpBasicConfigurer<HttpSecurity> configurer) {
    configurer.realmName(StringUtils.defaultIfBlank(basicAuthProperties.getRealm(), defaultRealmName));
  }

  @Override
  public void configure(HttpSecurity http) {
  }

  private void patchAuthenticationObjectFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();
    if (authentication instanceof AbstractAuthenticationToken) {
      String userName = authentication.getName();
      DefaultUserDetails userDetails = userInfo.get(userName);
      if (null == userDetails) log.warn("Seems user '{}' is logged in but didn't find info about it.", userName);
      ((AbstractAuthenticationToken) authentication).setDetails(userDetails);
    }
    else if (null != authentication) {
      log.warn("Authentication object is not of type AbstractAuthenticationToken: '{}' - Cannot set UserDetails...", authentication.getClass());
    }
    chain.doFilter(request, response);
  }
}
