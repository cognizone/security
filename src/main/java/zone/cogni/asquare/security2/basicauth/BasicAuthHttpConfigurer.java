package zone.cogni.asquare.security2.basicauth;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import zone.cogni.asquare.security2.AsquareHttpConfigurer;

import javax.annotation.PostConstruct;

@RequiredArgsConstructor
public class BasicAuthHttpConfigurer extends AsquareHttpConfigurer<BasicAuthHttpConfigurer> {
  private static final String[] emptyStringArray = new String[0];
  private static final String defaultRealmName = "Who are you?";

  private final BasicAuthProperties basicAuthProperties;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;

  @PostConstruct
  @SneakyThrows
  private void init() {
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
        .realmName(StringUtils.defaultIfBlank(basicAuthProperties.getRealm(), defaultRealmName));

  }

  @Override
  public void configure(HttpSecurity http) {
  }

}
