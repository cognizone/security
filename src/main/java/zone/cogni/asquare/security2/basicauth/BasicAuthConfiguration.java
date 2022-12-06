package zone.cogni.asquare.security2.basicauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

@Configuration
public class BasicAuthConfiguration {

  @Bean
  @ConfigurationProperties(prefix = "cognizone.security.basic-auth")
  public BasicAuthProperties basicAuthProperties() {
    return new BasicAuthProperties();
  }

  @Bean
  public BasicAuthHttpConfigurer basicAuthHttpConfigurer(AuthenticationManagerBuilder authenticationManagerBuilder) {
    return new BasicAuthHttpConfigurer(basicAuthProperties(), authenticationManagerBuilder);
  }
}
