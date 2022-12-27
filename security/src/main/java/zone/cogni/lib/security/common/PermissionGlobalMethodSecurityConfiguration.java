package zone.cogni.lib.security.common;

import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import zone.cogni.lib.security.permission.PermissionService;
import zone.cogni.lib.security.permission.PermissionServiceConfiguration;
import zone.cogni.lib.security.permission.handler.PermissionAccessDecisionVoter;
import zone.cogni.lib.security.permission.handler.PermissionMethodSecurityMetadataSource;

import javax.inject.Inject;
import java.util.Optional;

@Import(PermissionServiceConfiguration.class)
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public abstract class PermissionGlobalMethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

  @Inject
  private Optional<PermissionService> permissionService;

  @Override
  protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
    return permissionService.isPresent() ? new PermissionMethodSecurityMetadataSource() : null;
  }

  @Override
  protected AccessDecisionManager accessDecisionManager() {
    AffirmativeBased manager = (AffirmativeBased) super.accessDecisionManager();
    permissionService.ifPresent(service -> manager.getDecisionVoters().add(new PermissionAccessDecisionVoter(service)));
    return manager;
  }
}
