package zone.cogni.lib.security.generic;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.common.BasicAuthUser;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

public abstract class GenericSecurity {

  @Nullable
  public abstract LoginInfo login(HttpServletRequest request);

  @Nonnull
  public Map<String, BasicAuthUser> getBasicAuthUsers() {
    return new HashMap<>();
  }


  @RequiredArgsConstructor
  @Getter
  public static class LoginInfo {
    @Nonnull
    private final AbstractAuthenticationToken authentication;
    @Nonnull
    private final DefaultUserDetails userDetails;
  }
}
