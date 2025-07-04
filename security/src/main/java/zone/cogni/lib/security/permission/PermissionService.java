package zone.cogni.lib.security.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import jakarta.annotation.Nullable;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@SuppressWarnings({"WeakerAccess", "unused"})
@Slf4j
public class PermissionService {

  private final Map<String, Set<String>> roleName2permissionString = Collections.synchronizedMap(new HashMap<>());
  private final Set<String> defaultPermissionStrings;
  private final Map<String, Permission> permissionByName;

  @SneakyThrows
  public PermissionService(Resource roleAccess) {
    log.info("Reading roleAccess {}", roleAccess.getFilename());
    try (InputStream inputStream = roleAccess.getInputStream()) {
      Map<?, ?> jsonData = new ObjectMapper().readValue(inputStream, Map.class);

      defaultPermissionStrings = Collections.synchronizedSet(jsonArray2ProjectPermissionStringSet(jsonData.get("rulesDefault")));

      @SuppressWarnings("unchecked")
      Map<String, Map<String, Object>> roles = (Map<String, Map<String, Object>>) jsonData.get("roles");
      if (null == roles) {
        log.warn("No roles found in roleAccess file");
      }
      else {
        for (Map.Entry<String, Map<String, Object>> entry : roles.entrySet()) {
          String role = entry.getKey();
          Map<String, Object> values = entry.getValue();
          roleName2permissionString.put(StringUtils.lowerCase(role), jsonArray2ProjectPermissionStringSet(values.get("rules")));
        }
      }
    }

    permissionByName = Collections.synchronizedMap(initPermissionsByName());
    log.info("Role names for permissions {}", roleName2permissionString);
  }

  private Map<String, Permission> initPermissionsByName() {
    Map<String, Permission> result = new HashMap<>();
    for (Permission permission : Permission.values()) {
      if (result.containsKey(permission.name())) throw new RuntimeException("Duplicate permission by name: " + permission);
      result.put(permission.name(), permission);

      String value = getPermissionValue(permission);
      if (StringUtils.isNotBlank(value)) {
        Permission previous = result.put(value, permission);
        if (null != previous && previous == permission) throw new RuntimeException("Duplicate permission: " + previous + " vs " + permission);
      }
    }
    return result;
  }

  private Set<String> jsonArray2ProjectPermissionStringSet(Object jsonArrayObject) {
    //noinspection unchecked
    return null == jsonArrayObject ? Collections.emptySet() : new HashSet<>((Collection<String>) jsonArrayObject);
  }

  /**
   * Get all permissions for an Authentication.
   */
  public Set<Permission> getPermissionEnums(Authentication authentication) {
    Set<String> roles = getRoles(authentication);
    log.info("Available roles {}", roles);

    return roles.stream()
                .map(this::getPermissionEnums)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
  }

  /**
   * Get all permissions for an Authentication.
   */
  public Set<String> getPermissions(Authentication authentication) {
    Set<String> roles = getRoles(authentication);
    log.info("Available roles {}", roles);

    return roles.stream()
                .map(this::getPermissions)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
  }

  /**
   * Get permissions for a given role.
   * Permission values that don't have an associated Permission object will just be skipped.
   */
  public Set<Permission> getPermissionEnums(String roleName) {
    return getPermissions(roleName)
            .stream()
            .map(permissionByName::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
  }

  /**
   * Get permissions for a given role.
   */
  public Set<String> getPermissions(String roleName) {
    Set<String> result = new HashSet<>(defaultPermissionStrings);
    result.addAll(roleName2permissionString.getOrDefault(StringUtils.lowerCase(roleName), Collections.emptySet()));
    return result;
  }

  /**
   * Check if an Authentication contains the given permission.
   */
  public boolean hasPermissionEnum(Authentication authentication, Permission permission) {
    return hasAnyPermissionEnum(authentication, permission);
  }

  /**
   * Check if an Authentication contains the given permission.
   */
  public boolean hasPermission(Authentication authentication, String permission) {
    return hasAnyPermission(authentication, permission);
  }

  /**
   * Check if an Authentication contains <strong>any</strong> of the given permissions.
   */
  public boolean hasAnyPermissionEnum(Authentication authentication, Permission... projectPermissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(projectPermissions)
                 .anyMatch(projectPermission -> hasPermissionEnum(roles, projectPermission));
  }

  /**
   * Check if an Authentication contains <strong>any</strong> of the given permissions.
   */
  public boolean hasAnyPermission(Authentication authentication, String... permissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(permissions)
                 .anyMatch(projectPermission -> hasPermission(roles, projectPermission));
  }

  /**
   * Check if an Authentication contains <strong>all</strong> of the given permissions.
   */
  public boolean hasAllPermissions(Authentication authentication, String... permissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(permissions)
                 .allMatch(permission -> hasPermission(roles, permission));
  }

  /**
   * Check if an Authentication contains <strong>all</strong> of the given permissions.
   */
  public boolean hasAllPermissionEnum(Authentication authentication, Permission... projectPermissions) {
    Set<String> roles = getRoles(authentication);
    return Arrays.stream(projectPermissions)
                 .allMatch(projectPermission -> hasPermissionEnum(roles, projectPermission));
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

  private boolean hasPermissionEnum(Set<String> roles, Permission projectPermission) {
    if (hasPermission(roles, projectPermission.name())) return true;
    String permissionValue = getPermissionValue(projectPermission);
    return StringUtils.isNotBlank(permissionValue) && hasPermission(roles, permissionValue);
  }

  private boolean hasPermission(Set<String> roles, String projectPermission) {
    if (defaultPermissionStrings.contains(projectPermission)) return true;
    return roles.stream()
                .map(StringUtils::lowerCase)
                .map(roleName2permissionString::get)
                .filter(Objects::nonNull)
                .anyMatch(projectPermissions -> projectPermissions.contains(projectPermission));
  }

  @Nullable
  private static String getPermissionValue(Object permission) {
    return permission instanceof PermissionValue ? ((PermissionValue) permission).getValue() : null;
  }

}
