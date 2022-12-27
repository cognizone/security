package zone.cogni.lib.security.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@SuppressWarnings({"WeakerAccess", "unused"})
@Slf4j
public class PermissionService {

  private final Map<String, Set<Permission>> roleName2permissions = Collections.synchronizedMap(new HashMap<>());
  private final Set<Permission> defaultPermissions;

  @SneakyThrows
  public PermissionService(Resource roleAccess) {
    log.info("Reading roleAccess {}", roleAccess.getFilename());
    try (InputStream inputStream = roleAccess.getInputStream()) {
      Map<?, ?> jsonData = new ObjectMapper().readValue(inputStream, Map.class);

      defaultPermissions = jsonArray2ProjectPermissionSet(jsonData.get("rulesDefault"));

      @SuppressWarnings("unchecked")
      Map<String, Map<String, Object>> roles = (Map<String, Map<String, Object>>) jsonData.get("roles");
      if(null == roles) {
        log.warn("No roles found in roleAccess file");
      }
      else {
        for (Map.Entry<String, Map<String, Object>> entry : roles.entrySet()) {
          String role = entry.getKey();
          Map<String, Object> values = entry.getValue();
          roleName2permissions.put(StringUtils.lowerCase(role), jsonArray2ProjectPermissionSet(values.get("rules")));
        }
      }
    }
    log.info("Role names for permissions {}", roleName2permissions);
  }

  /**
   * Get permissions for a given role.
   */
  public Set<Permission> getPermissions(String roleName) {
    return roleName2permissions.getOrDefault(StringUtils.lowerCase(roleName), Collections.emptySet());
  }

  private Set<Permission> jsonArray2ProjectPermissionSet(Object jsonArrayObject) {
    if (null == jsonArrayObject) return Collections.emptySet();

    //noinspection unchecked
    Collection<String> jsonArray = (Collection<String>) jsonArrayObject;
    return jsonArray.stream()
                    .map(this::valueOf)
                    .collect(Collectors.toCollection(() -> Collections.synchronizedSet(EnumSet.noneOf(Permission.class))));
  }

  /**
   * Check if an Authentication contains the given permission.
   */
  public boolean hasPermission(Authentication authentication, String permission) {
    return hasAnyPermissionEnum(authentication, valueOf(permission));
  }

  /**
   * Check if an Authentication contains <strong>any</strong> of the given permissions.
   */
  public boolean hasAnyPermission(Authentication authentication, String... permissions) {
    return Arrays.stream(permissions)
                 .map(this::valueOf)
                 .anyMatch(projectPermission -> hasPermissionEnum(authentication, projectPermission));
  }

  /**
   * Check if an Authentication contains the given permission.
   */
  public boolean hasPermissionEnum(Authentication authentication, Permission permission) {
    return hasAnyPermissionEnum(authentication, permission);
  }

  /**
   * Check if an Authentication contains <strong>any</strong> of the given permissions.
   */
  public boolean hasAnyPermissionEnum(Authentication authentication, Permission... projectPermissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(projectPermissions)
                 .anyMatch(projectPermission -> hasPermission(roles, projectPermission));
  }

  /**
   * Check if an Authentication contains <strong>all</strong> of the given permissions.
   */
  public boolean hasAllPermissionEnum(Authentication authentication, Permission... projectPermissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(projectPermissions)
                 .allMatch(projectPermission -> hasPermission(roles, projectPermission));
  }

  /**
   * Get all permissions for an Authentication.
   */
  public Set<Permission> getPermissions(Authentication authentication) {
    Set<String> roles = getRoles(authentication);
    log.info("Available roles {}", roles);
    return Arrays.stream(Permission.values())
                 .filter(permission -> hasPermission(roles, permission))
                 .collect(Collectors.toSet());
  }

  /**
   * Get all roles for an Authentication.
   */
  public Set<String> getRoles(Authentication authentication) {
    if (null == authentication) return Collections.emptySet();
    return authentication.getAuthorities()
                         .stream()
                         .map(GrantedAuthority::getAuthority)
                         .map(value -> StringUtils.removeStartIgnoreCase(value, "role_"))
                         .collect(Collectors.toSet());
  }

  private boolean hasPermission(Set<String> roles, Permission projectPermission) {
    if (defaultPermissions.contains(projectPermission)) return true;
    return roles.stream()
                .map(StringUtils::lowerCase)
                .map(roleName2permissions::get)
                .filter(Objects::nonNull)
                .anyMatch(projectPermissions -> projectPermissions.contains(projectPermission));
  }

  private Permission valueOf(String value) {
    try {
      return Permission.valueOf(value);
    }
    catch (IllegalArgumentException e) {
      throw new RuntimeException("Permission does not have a value for '" + value + "'", e);
    }
  }
}
