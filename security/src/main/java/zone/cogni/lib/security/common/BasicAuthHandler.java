package zone.cogni.lib.security.common;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import zone.cogni.lib.security.DefaultUserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class BasicAuthHandler {

  //Should we Beanize these 2 ?
  private static final BasicAuthenticationConverter basicAuthenticationConverter = new BasicAuthenticationConverter();
  private static final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

  private final Map<String, BasicAuthUser> basicAuthUsers;

  public void handleFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
    handle((HttpServletRequest) request);
    chain.doFilter(request, response);
  }

  private void handle(HttpServletRequest request) {
    Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
    if (null != currentAuthentication && currentAuthentication.isAuthenticated()) return;

    UsernamePasswordAuthenticationToken requestUsernamePassword = parseRequest(request);
    if (null == requestUsernamePassword) return;

    BasicAuthUser user = basicAuthUsers.get(requestUsernamePassword.getName());
    if (null == user) return;

    if (!passwordEncoder.matches((CharSequence) requestUsernamePassword.getCredentials(), user.getPassword())) return;

    DefaultUserDetails defaultUserDetails = user.toDefaultUserDetails(requestUsernamePassword.getName());
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(requestUsernamePassword.getName(), "*******", defaultUserDetails.getAuthorities());
    authentication.setDetails(defaultUserDetails);
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  private UsernamePasswordAuthenticationToken parseRequest(HttpServletRequest request) {
    try {
      return basicAuthenticationConverter.convert(request);
    }
    catch (Exception ex) { //can happen if somebody sends weirdo Authorization header... we will just ignore
      log.warn("Failed to convert basic-auth: {}", ex.getMessage());
      return null;
    }
  }
}
