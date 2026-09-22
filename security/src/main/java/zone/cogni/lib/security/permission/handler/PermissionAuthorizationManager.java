package zone.cogni.lib.security.permission.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import zone.cogni.lib.security.permission.HasPermission;
import zone.cogni.lib.security.permission.Permission;
import zone.cogni.lib.security.permission.PermissionService;

import java.util.function.Supplier;

@RequiredArgsConstructor
@Slf4j
public class PermissionAuthorizationManager implements AuthorizationManager<MethodInvocation> {
  private final PermissionService permissionService;

  @Override
  public AuthorizationDecision authorize(Supplier<? extends Authentication> authentication, MethodInvocation invocation) {
    HasPermission methodAnnotation = invocation.getMethod().getAnnotation(HasPermission.class);
    HasPermission classAnnotation = invocation.getMethod().getDeclaringClass().getAnnotation(HasPermission.class);

    if (methodAnnotation == null && classAnnotation == null) {
      return null; // abstain
    }

    Authentication auth = authentication.get();

    if (methodAnnotation != null) {
      AuthorizationDecision decision = checkPermission(auth, methodAnnotation);
      if (decision != null && !decision.isGranted()) return decision;
    }

    if (classAnnotation != null) {
      AuthorizationDecision decision = checkPermission(auth, classAnnotation);
      if (decision != null && !decision.isGranted()) return decision;
    }

    return new AuthorizationDecision(true);
  }

  private AuthorizationDecision checkPermission(Authentication authentication, HasPermission hasPermission) {
    Permission[] anyPermissions = hasPermission.any();
    if (anyPermissions.length == 0) anyPermissions = hasPermission.value();
    Permission[] allPermissions = hasPermission.all();

    if (ArrayUtils.isNotEmpty(allPermissions)) {
      if (!permissionService.hasAllPermissionEnum(authentication, allPermissions)) {
        log.debug("Not all permissions ({}) for {}", StringUtils.join(allPermissions), authentication);
        return new AuthorizationDecision(false);
      }
      log.debug("Ok for all permissions ({}) for {}", StringUtils.join(allPermissions), authentication);
    }

    if (ArrayUtils.isNotEmpty(anyPermissions)) {
      if (!permissionService.hasAnyPermissionEnum(authentication, anyPermissions)) {
        log.debug("Not any permissions ({}) for {}", StringUtils.join(anyPermissions), authentication);
        return new AuthorizationDecision(false);
      }
      log.debug("Ok for any permissions ({}) for {}", StringUtils.join(anyPermissions), authentication);
    }

    return new AuthorizationDecision(true);
  }
}
