package zone.cogni.lib.security.off;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import zone.cogni.lib.security.common.PermissionGlobalMethodSecurityConfiguration;

@Configuration
@Slf4j
public class OffConfiguration extends PermissionGlobalMethodSecurityConfiguration {
  @Bean
  public OffHttpConfigurer offHttpConfigurer() {
    return new OffHttpConfigurer();
  }

}
