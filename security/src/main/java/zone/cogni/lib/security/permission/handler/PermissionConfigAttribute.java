package zone.cogni.lib.security.permission.handler;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.ConfigAttribute;
import zone.cogni.lib.security.permission.Permission;

@RequiredArgsConstructor
@Getter
class PermissionConfigAttribute implements ConfigAttribute {
  private static final long serialVersionUID = 1L;
  private final Permission[] anyPermissions;
  private final Permission[] allPermissions;

  @Override
  public String getAttribute() {
    return null;
  }
}
