package zone.cogni.lib.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableSecurity
@RequiredArgsConstructor
@EnableWebMvc
public class EnableSecurityInTestConfiguration {
  private final SecurityHttpConfigurer<? extends SecurityHttpConfigurer> security2HttpConfigurer;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());
    security2HttpConfigurer.init(http);
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/public/**").permitAll()
            .requestMatchers("/private/**").authenticated()
            .anyRequest().denyAll()
    );
    return http.build();
  }
}
