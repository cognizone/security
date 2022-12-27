package zone.cogni.lib.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public abstract class SecurityHttpConfigurer<T extends SecurityHttpConfigurer<T>> extends AbstractHttpConfigurer<T, HttpSecurity> {
}
