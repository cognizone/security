package zone.cogni.lib.security;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.annotation.Nonnull;
import java.util.Collection;

@Data
@NoArgsConstructor
public class DefaultUserDetails implements UserDetails {
  private static final long serialVersionUID = 1L;

  @Nonnull
  private Collection<GrantedAuthority> authorities;
  @Nonnull
  private String username;
  @Nonnull
  private String loginId;

  private String email;
  private String displayName;

  @Override
  public String getPassword() {
    return "https://youtu.be/AnWmF5Fq0sg";
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
