package zone.cogni.lib.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableSecurity
@RequiredArgsConstructor
public class EnableSecurityInTestConfiguration {
  private final SecurityHttpConfigurer<? extends SecurityHttpConfigurer> security2HttpConfigurer;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .apply(security2HttpConfigurer)
        .and()
        .authorizeRequests()
        .antMatchers("/public/**").permitAll()
        .antMatchers("/private/**").authenticated()
        .anyRequest().denyAll();
    return http.build();
  }
}
