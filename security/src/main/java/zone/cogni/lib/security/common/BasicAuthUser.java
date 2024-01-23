package zone.cogni.lib.security.common;

import lombok.Data;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import zone.cogni.lib.security.DefaultUserDetails;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Data
public class BasicAuthUser {
  @ToString.Exclude
  private String password;
  private String displayName;
  private String email;
  private List<String> roles = new ArrayList<>(); //init so we allow empty config
  private Map<String, String> additional = new HashMap<>();
  
  public DefaultUserDetails toDefaultUserDetails(String username) {
    List<GrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    return new DefaultUserDetails()
            .setAuthorities(authorities)
            .setDisplayName(StringUtils.firstNonBlank(displayName, "API: " + username))
            .setLoginId(username)
            .setEmail(email)
            .setUsername(username);
  }
}
