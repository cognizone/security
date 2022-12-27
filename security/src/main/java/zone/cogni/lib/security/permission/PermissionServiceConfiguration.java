package zone.cogni.lib.security.permission;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
@ConditionalOnProperty(prefix = "cognizone.security.permission-service", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class PermissionServiceConfiguration {
  @Value("${cognizone.security.permission-service.roleAccess}")
  private final Resource roleAccess;

  @Bean
  public PermissionService permissionService() {
    return new PermissionService(roleAccess);
  }

}
