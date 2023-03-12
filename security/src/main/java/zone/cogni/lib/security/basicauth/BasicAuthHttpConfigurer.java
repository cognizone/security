package zone.cogni.lib.security.basicauth;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.common.GlobalProperties;
import zone.cogni.lib.security.common.LogoutConfigurer;

import javax.annotation.PostConstruct;

@RequiredArgsConstructor
@Slf4j
public class BasicAuthHttpConfigurer extends SecurityHttpConfigurer<BasicAuthHttpConfigurer> {
  private static final String[] emptyStringArray = new String[0];
  private static final String defaultRealmName = "Who are you?";

  private final GlobalProperties globalProperties;
  private final BasicAuthProperties basicAuthProperties;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;

  @PostConstruct
  @SneakyThrows
  private void init() {
    log.info("Initializing basic-auth security");
    InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer = authenticationManagerBuilder.inMemoryAuthentication();
    basicAuthProperties.getUsers()
                       .forEach((key, value) -> addUser(configurer, key, value));
  }

  private void addUser(InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer, String userName, BasicAuthProperties.User user) {
    configurer.withUser(userName)
              .password(user.getPassword())
              .authorities(user.getRoles().toArray(emptyStringArray));
  }

  @Override
  @SneakyThrows
  public void init(HttpSecurity http) {
    http.httpBasic()
        .realmName(StringUtils.defaultIfBlank(basicAuthProperties.getRealm(), defaultRealmName)).and()
        .apply(new LogoutConfigurer(globalProperties.getLogout()));
  }

  @Override
  public void configure(HttpSecurity http) {
  }

}
