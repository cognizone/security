package zone.cogni.lib.security.generic.impl;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserViaHeaderAuthentication extends AbstractAuthenticationToken {
  private final String userId;

  public UserViaHeaderAuthentication(String userId, Collection<GrantedAuthority> authorities) {
    super(authorities);
    this.userId = userId;
  }

  @Override
  public String getName() {
    return userId;
  }

  @Override
  public Object getCredentials() {
    return "xxx";
  }

  @Override
  public Object getPrincipal() {
    return userId;
  }

}
