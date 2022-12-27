package zone.cogni.lib.security.permission.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import zone.cogni.lib.security.permission.Permission;
import zone.cogni.lib.security.permission.PermissionService;

import java.util.Collection;

@RequiredArgsConstructor
@Slf4j
public class PermissionAccessDecisionVoter implements AccessDecisionVoter<Object> {
  private final PermissionService permissionService;

  @Override
  public boolean supports(ConfigAttribute attribute) {
    return attribute instanceof PermissionConfigAttribute;
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return true;
  }

  @Override
  public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
    int result = ACCESS_ABSTAIN;
    for (ConfigAttribute attribute : attributes) {
      if (!(attribute instanceof PermissionConfigAttribute)) continue;

      Permission[] allPermissions = ((PermissionConfigAttribute) attribute).getAllPermissions();
      if (ArrayUtils.isNotEmpty(allPermissions)) {
        if (!permissionService.hasAllPermissionEnum(authentication, allPermissions)) {
          log.debug("Not all permissions ({}) for {}", StringUtils.join(allPermissions), authentication);
          return ACCESS_DENIED;
        }
        log.debug("Ok for all permissions ({}) for {}", StringUtils.join(allPermissions), authentication);
        result = ACCESS_GRANTED;
      }

      Permission[] anyPermissions = ((PermissionConfigAttribute) attribute).getAnyPermissions();
      if (ArrayUtils.isNotEmpty(anyPermissions)) {
        if (!permissionService.hasAnyPermissionEnum(authentication, anyPermissions)) {
          log.debug("Not any permissions ({}) for {}", StringUtils.join(anyPermissions), authentication);
          return ACCESS_DENIED;
        }
        log.debug("Ok for any permissions ({}) for {}", StringUtils.join(anyPermissions), authentication);
        result = ACCESS_GRANTED;
      }
    }
    return result;
  }


}
