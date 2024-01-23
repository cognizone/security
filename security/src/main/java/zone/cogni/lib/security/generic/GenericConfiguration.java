package zone.cogni.lib.security.generic;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import zone.cogni.lib.security.common.BasicAuthHandler;
import zone.cogni.lib.security.common.PermissionGlobalMethodSecurityConfiguration;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class GenericConfiguration extends PermissionGlobalMethodSecurityConfiguration {
  private final GenericSecurity genericSecurity;

  @Bean
  public BasicAuthHandler basicAuthHandler() {
    return new BasicAuthHandler(genericSecurity.getBasicAuthUsers());
  }

  @Bean
  public GenericHttpConfigurer genericHttpConfigurer() {
    return new GenericHttpConfigurer(globalProperties(), genericSecurity, basicAuthHandler());
  }
}
