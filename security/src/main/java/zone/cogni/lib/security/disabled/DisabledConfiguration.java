package zone.cogni.lib.security.disabled;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class DisabledConfiguration {
  @Bean
  public DisabledHttpConfigurer disabledHttpConfigurer() {
    return new DisabledHttpConfigurer();
  }

}
