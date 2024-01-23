package zone.cogni.lib.security.generic;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.CompositeFilter;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.common.BasicAuthHandler;
import zone.cogni.lib.security.common.GlobalProperties;
import zone.cogni.lib.security.common.LogoutConfigurer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
public class GenericHttpConfigurer extends SecurityHttpConfigurer<GenericHttpConfigurer> {

  private final GlobalProperties globalProperties;
  private final GenericSecurity genericSecurity;
  private final BasicAuthHandler basicAuthHandler;

  @Override
  @SneakyThrows
  public void init(HttpSecurity http) {
    CompositeFilter compositeFilter = new CompositeFilter();
    compositeFilter.setFilters(List.of(this::initAuthentication, basicAuthHandler::handleFilter));
    http.addFilterBefore(compositeFilter, LogoutFilter.class)
        .apply(new LogoutConfigurer(globalProperties.getLogout()));
  }

  @Override
  public void configure(HttpSecurity http) {
  }

  private void initAuthentication(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    GenericSecurity.LoginInfo loginInfo = genericSecurity.login((HttpServletRequest) request);
    if (null != loginInfo) {
      AbstractAuthenticationToken authentication = loginInfo.getAuthentication();
      authentication.setAuthenticated(true);
      authentication.setDetails(loginInfo.getUserDetails());
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    chain.doFilter(request, response);
  }

}
