package zone.cogni.lib.security;

import org.springframework.context.annotation.Import;
import zone.cogni.lib.security.generic.SecurityConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(SecurityConfiguration.class)
public @interface EnableSecurity {
}
