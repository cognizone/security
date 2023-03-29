package zone.cogni.lib.security.saml2;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import zone.cogni.lib.security.DefaultUserDetails;

public class ExtendedSaml2Authentication extends AbstractAuthenticationToken {
  private final Saml2Authentication saml2Authentication;
  private final DefaultUserDetails userDetails;

  public ExtendedSaml2Authentication(DefaultUserDetails userDetails, Saml2Authentication saml2Authentication) {
    super(userDetails.getAuthorities());
    this.userDetails = userDetails;
    this.saml2Authentication = saml2Authentication;
    setAuthenticated(true);
  }

  @Override
  public DefaultUserDetails getDetails() {
    return userDetails;
  }

  @Override
  public Object getPrincipal() {
    return saml2Authentication.getPrincipal();
  }

  public String getSaml2Response() {
    return saml2Authentication.getSaml2Response();
  }

  @Override
  public Object getCredentials() {
    return saml2Authentication.getSaml2Response();
  }

}
