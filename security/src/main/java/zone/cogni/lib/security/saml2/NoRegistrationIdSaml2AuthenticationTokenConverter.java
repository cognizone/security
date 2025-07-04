package zone.cogni.lib.security.saml2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;


/**
 * Copied from <code>org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter</code>
 * This one is needed if you want to have a <code>assertionConsumerServiceUrl</code> that doesn't end with {registrationId}.
 * The default implementation gets the registrationId from the end of the url.
 */
@Slf4j
@RequiredArgsConstructor
public final class NoRegistrationIdSaml2AuthenticationTokenConverter implements AuthenticationConverter {

  private static Base64 BASE64 = new Base64(0, new byte[] {'\n' }, false, CodecPolicy.STRICT);

  private Function<HttpServletRequest, AbstractSaml2AuthenticationRequest> loader = new HttpSessionSaml2AuthenticationRequestRepository()::loadAuthenticationRequest;;

  private final RelyingPartyRegistration relyingPartyRegistration;

  @Override
  public Saml2AuthenticationToken convert(HttpServletRequest request) {
//    RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationResolver.convert(request);
//    if (relyingPartyRegistration == null) {
//      return null;
//    }

    String saml2Response = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
    log.info("convert asked... samlResponse is found: {}", saml2Response != null);
    if (saml2Response == null) {
      return null;
    }
    byte[] b = samlDecode(saml2Response);
    saml2Response = inflateIfRequired(request, b);
    AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
    return new Saml2AuthenticationToken(relyingPartyRegistration, saml2Response, authenticationRequest);
  }

  /**
   * Use the given {@link Saml2AuthenticationRequestRepository} to load authentication
   * request.
   * @param authenticationRequestRepository the
   * {@link Saml2AuthenticationRequestRepository} to use
   * @since 5.6
   */
  public void setAuthenticationRequestRepository(
          Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
    Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
    this.loader = authenticationRequestRepository::loadAuthenticationRequest;
  }

  private AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
    return this.loader.apply(request);
  }

  private String inflateIfRequired(HttpServletRequest request, byte[] b) {
    if (HttpMethod.GET.matches(request.getMethod())) {
      return samlInflate(b);
    }
    return new String(b, StandardCharsets.UTF_8);
  }

  private byte[] samlDecode(String base64EncodedPayload) {
    try {
      return BASE64.decode(base64EncodedPayload);
    }
    catch (Exception ex) {
      throw new Saml2AuthenticationException(
              new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Failed to decode SAMLResponse"), ex);
    }
  }

  private String samlInflate(byte[] b) {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
      inflaterOutputStream.write(b);
      inflaterOutputStream.finish();
      return out.toString(StandardCharsets.UTF_8.name());
    }
    catch (Exception ex) {
      throw new Saml2AuthenticationException(
              new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Unable to inflate string"), ex);
    }
  }

}
