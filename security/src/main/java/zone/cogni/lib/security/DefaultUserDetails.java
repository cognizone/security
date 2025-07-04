package zone.cogni.lib.security;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.annotation.Nonnull;
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
  private String firstName;
  private String lastName;

  /**
   * Returns displayName or concatenation of firstname and lastname if displayName is not set.
   */
  public String getCalculatedDisplayName() {
    if (StringUtils.isNotBlank(displayName)) return displayName;
    return StringUtils.trim(StringUtils.defaultString(firstName, "") + " " + StringUtils.defaultString(lastName, ""));
  }

  /**
   * Returns first name or as fallback the part before the first space in displayName (null if no first name or no space in displayName).
   */
  public String getCalculatedFirstName() {
    if (StringUtils.isNotBlank(firstName)) return firstName;
    if (StringUtils.containsNone(displayName, " ")) return null;
    return StringUtils.substringBefore(displayName, ' ');
  }

  /**
   * Returns last name or as fallback the part after the first space in displayName (if no last name and no space in displayName, the full displayName is returned).
   */
  public String getCalculatedLastName() {
    if (StringUtils.isNotBlank(lastName)) return lastName;
    return StringUtils.substringAfter(displayName, ' ');
  }

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
