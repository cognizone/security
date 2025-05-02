package zone.cogni.lib.security.generic.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.common.BasicAuthUser;
import zone.cogni.lib.security.generic.GenericSecurity;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public class UserViaHeaderSecurity extends GenericSecurity {

  private final Map<String, BasicAuthUser> basicAuthUsers;

  @Nullable
  @Override
  public LoginInfo login(HttpServletRequest request) {
    String userId = request.getHeader("user-id");
    if (!"jef".equals(userId)) return null;

    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority("jow"));
    UserViaHeaderAuthentication authentication = new UserViaHeaderAuthentication(userId, authorities);
    DefaultUserDetails userDetails = createUserDetails(userId, authorities);
    return new LoginInfo(authentication, userDetails);
  }

  private DefaultUserDetails createUserDetails(String userId, List<GrantedAuthority> authorities) {
    return new DefaultUserDetails()
            .setAuthorities(authorities)
            .setDisplayName("Jef louis")
            .setEmail("jef.louis@mail.com")
            .setLoginId(userId)
            .setUsername(userId);

  }

  @Nonnull
  @Override
  public Map<String, BasicAuthUser> getBasicAuthUsers() {
    return basicAuthUsers;
  }
}
