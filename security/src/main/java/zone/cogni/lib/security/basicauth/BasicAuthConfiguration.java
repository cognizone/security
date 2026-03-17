package zone.cogni.lib.security.basicauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import zone.cogni.lib.security.common.PermissionMethodSecurityConfiguration;

@Configuration
public class BasicAuthConfiguration extends PermissionMethodSecurityConfiguration {

  @Bean
  @ConfigurationProperties(prefix = "cognizone.security.basic-auth")
  public BasicAuthProperties basicAuthProperties() {
    return new BasicAuthProperties();
  }

  @Bean
  public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
    return new InMemoryUserDetailsManager();
  }

  @Bean
  public BasicAuthHttpConfigurer basicAuthHttpConfigurer(InMemoryUserDetailsManager inMemoryUserDetailsManager) {
    return new BasicAuthHttpConfigurer(globalProperties(), basicAuthProperties(), inMemoryUserDetailsManager);
  }
}
