package zone.cogni.lib.security.common;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@RequiredArgsConstructor
public class LogoutConfigurer extends AbstractHttpConfigurer<LogoutConfigurer, HttpSecurity> {
  private final GlobalProperties.Logout logout;

  @Override
  public void init(HttpSecurity http) throws Exception {
    if (StringUtils.isBlank(logout.getUrl())) return;

    http.logout(configurer -> {
      configurer.logoutUrl(logout.getUrl());
      if (StringUtils.isNotBlank(logout.getSuccessUrl())) configurer.logoutSuccessUrl(logout.getSuccessUrl());
    });
  }

  @Override
  public void configure(HttpSecurity http) {
  }
}
