package zone.cogni.lib.security.off;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class OffConfiguration {
  @Bean
  public OffHttpConfigurer offHttpConfigurer() {
    return new OffHttpConfigurer();
  }

}
