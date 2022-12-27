package zone.cogni.lib.security.permission.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import zone.cogni.lib.security.permission.HasPermission;
import zone.cogni.lib.security.permission.Permission;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Slf4j
public class PermissionMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {
  @Override
  public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
    HasPermission methodHasPermission = method.getAnnotation(HasPermission.class);
    HasPermission classHasPermission = targetClass.getAnnotation(HasPermission.class);

    if (null == methodHasPermission && null == classHasPermission) return Collections.emptyList();

    List<ConfigAttribute> attributes = new ArrayList<>();
    addAttribute(attributes, methodHasPermission);
    addAttribute(attributes, classHasPermission);
    log.debug("PermissionMethodSecurityMetadataSource init with attributeCount [{} --  {}]: {}", method, targetClass, attributes.size());
    return attributes;
  }

  private void addAttribute(List<ConfigAttribute> attributes, HasPermission hasPermission) {
    if (null == hasPermission) return;

    Permission[] anyPermissions = hasPermission.any();
    if (anyPermissions.length == 0) anyPermissions = hasPermission.value();
    Permission[] allPermissions = hasPermission.all();
    if (anyPermissions.length > 0 || allPermissions.length > 0) attributes.add(new PermissionConfigAttribute(anyPermissions, allPermissions));
  }

  @Override
  public Collection<ConfigAttribute> getAllConfigAttributes() {
    return Collections.emptyList();
  }
}
