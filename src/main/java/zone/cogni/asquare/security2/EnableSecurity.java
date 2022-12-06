package zone.cogni.asquare.security2;

import org.springframework.context.annotation.Import;
import zone.cogni.asquare.security2.generic.SecurityConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(SecurityConfiguration.class)
public @interface EnableSecurity {
}
