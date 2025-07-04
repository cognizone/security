package zone.cogni.lib.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@EnableSecurity
@RequiredArgsConstructor
public class EnableSecurityInTestConfiguration {
  private final SecurityHttpConfigurer<? extends SecurityHttpConfigurer> security2HttpConfigurer;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable)
               .with(security2HttpConfigurer, Customizer.withDefaults())
               .authorizeHttpRequests(this::customizeAuthorization)
               .build();
  }

  @Bean(name = "mvcHandlerMappingIntrospector")
  public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
    return new HandlerMappingIntrospector();
  }

  private void customizeAuthorization(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizeHttpRequestsCustomizer) {
    authorizeHttpRequestsCustomizer
            .requestMatchers("/public/**").permitAll()
            .requestMatchers("/private/**").authenticated()
            .anyRequest().denyAll();
  }

}
