package zone.cogni.lib.security.permission;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@SuppressWarnings("NewMethodNamingConvention")
public @interface HasPermission {

  @AliasFor(attribute = "any")
  Permission[] value() default {};

  @AliasFor(attribute = "value")
  Permission[] any() default {};

  Permission[] all() default {};

}
