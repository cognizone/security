package zone.cogni.lib.security.common;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import zone.cogni.lib.security.permission.HasPermission;
import zone.cogni.lib.security.permission.PermissionService;
import zone.cogni.lib.security.permission.PermissionServiceConfiguration;
import zone.cogni.lib.security.permission.handler.PermissionAuthorizationManager;

@Import(PermissionServiceConfiguration.class)
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public abstract class PermissionMethodSecurityConfiguration {

  @Bean
  @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
  @ConditionalOnBean(PermissionService.class)
  public Advisor hasPermissionAuthorizationAdvisor(PermissionService permissionService) {
    AuthorizationManager<MethodInvocation> manager = new PermissionAuthorizationManager(permissionService);

    Pointcut classLevel = new AnnotationMatchingPointcut(HasPermission.class, true);
    Pointcut methodLevel = AnnotationMatchingPointcut.forMethodAnnotation(HasPermission.class);
    Pointcut pointcut = new ComposablePointcut(classLevel).union(methodLevel);

    AuthorizationManagerBeforeMethodInterceptor interceptor =
            new AuthorizationManagerBeforeMethodInterceptor(pointcut, manager);
    interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder() - 1);
    return interceptor;
  }

  @ConfigurationProperties(prefix = "cognizone.security.global-properties")
  @Bean
  public GlobalProperties globalProperties() {
    return new GlobalProperties();
  }

}
