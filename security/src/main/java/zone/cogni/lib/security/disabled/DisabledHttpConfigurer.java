package zone.cogni.lib.security.disabled;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import zone.cogni.lib.security.SecurityHttpConfigurer;

@RequiredArgsConstructor
@Slf4j
public class DisabledHttpConfigurer extends SecurityHttpConfigurer<DisabledHttpConfigurer> {


  @Override
  public void init(HttpSecurity http) {
  }

  @Override
  @SneakyThrows
  public void configure(HttpSecurity http) {
    http.authorizeRequests()
        .anyRequest()
        .permitAll();
  }

}
