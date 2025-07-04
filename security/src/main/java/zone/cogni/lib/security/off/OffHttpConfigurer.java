package zone.cogni.lib.security.off;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import zone.cogni.lib.security.SecurityHttpConfigurer;

@RequiredArgsConstructor
@Slf4j
public class OffHttpConfigurer extends SecurityHttpConfigurer<OffHttpConfigurer> {


  @Override
  @SneakyThrows
  public void init(HttpSecurity http) {
    //This needs to be configured here and not in configure method.
    //  Configure method will actually initialize the bean and not allow us to configure extra stuff when using the lib.
    http.authorizeHttpRequests(this::authorizeAll);
  }

  private void authorizeAll(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requestMatcherRegistry) {
    requestMatcherRegistry.anyRequest()
                          .permitAll();
  }

  @Override
  public void configure(HttpSecurity http) {
  }

}
