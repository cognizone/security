package zone.cogni.lib.security.basicauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import zone.cogni.lib.security.common.PermissionGlobalMethodSecurityConfiguration;

@Configuration
public class BasicAuthConfiguration extends PermissionGlobalMethodSecurityConfiguration {

  @Bean
  @ConfigurationProperties(prefix = "cognizone.security.basic-auth")
  public BasicAuthProperties basicAuthProperties() {
    return new BasicAuthProperties();
  }

  @Bean
  public BasicAuthHttpConfigurer basicAuthHttpConfigurer(AuthenticationManagerBuilder authenticationManagerBuilder) {
    return new BasicAuthHttpConfigurer(globalProperties(), basicAuthProperties(), authenticationManagerBuilder);
  }
}
