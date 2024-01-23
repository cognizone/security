package zone.cogni.lib.security.generic.impl;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import zone.cogni.lib.security.EnableSecurity;
import zone.cogni.lib.security.common.BasicAuthUser;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableSecurity
public class UserViaHeaderConfiguration {

  @Bean
  public UserViaHeaderSecurity luxSecurity() {
    return new UserViaHeaderSecurity(basicAuthUsers());
  }

  @Bean
  @ConfigurationProperties("project-stuff.or.aligned.with.security-lib.you-choose.basic-auth-users")
  public Map<String, BasicAuthUser> basicAuthUsers() {
    return new HashMap<>();
  }
}
