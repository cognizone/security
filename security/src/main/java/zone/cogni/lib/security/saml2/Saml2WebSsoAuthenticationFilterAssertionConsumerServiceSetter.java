package zone.cogni.lib.security.saml2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.ObjectPostProcessor ;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;

import java.net.MalformedURLException;
import java.net.URL;

@RequiredArgsConstructor
@Slf4j
class Saml2WebSsoAuthenticationFilterAssertionConsumerServiceSetter implements ObjectPostProcessor<Saml2WebSsoAuthenticationFilter> {
  private final String assertionConsumerServiceUrl;
  private final String contextPath;

  @Override
  public <O extends Saml2WebSsoAuthenticationFilter> O postProcess(O object) {
    String assertionConsumerServicePath = getAssertionConsumerServicePath();
    log.info("Will patch assertionConsumerServicePath in Saml2WebSsoAuthenticationFilter with {}", assertionConsumerServicePath);
    object.setFilterProcessesUrl(assertionConsumerServicePath);
    return object;
  }

  private String getAssertionConsumerServicePath() {
    try {
      String path = new URL(assertionConsumerServiceUrl).getPath();
      if (!path.startsWith(contextPath)) throw new RuntimeException("Path of AssertionConsumerServiceUrl does not start with " + contextPath);
      return "/" + StringUtils.removeStart(path, contextPath);
    }
    catch (MalformedURLException e) {
      throw new RuntimeException("Invalid assertionConsumerServiceUrl: [" + assertionConsumerServiceUrl + "]", e);
    }
  }
}
