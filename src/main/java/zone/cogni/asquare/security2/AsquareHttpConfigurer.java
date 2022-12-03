package zone.cogni.asquare.security2;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public abstract class AsquareHttpConfigurer<T extends AsquareHttpConfigurer<T>> extends AbstractHttpConfigurer<T, HttpSecurity> {
}
