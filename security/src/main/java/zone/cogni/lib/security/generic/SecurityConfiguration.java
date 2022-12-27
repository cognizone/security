package zone.cogni.lib.security.generic;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.basicauth.EnableBasicAuth;
import zone.cogni.lib.security.permission.PermissionServiceConfiguration;
import zone.cogni.lib.security.saml2.EnableSaml2;

import javax.annotation.PostConstruct;

@Configuration
@Import(PermissionServiceConfiguration.class)
@Slf4j
public class SecurityConfiguration {

  @PostConstruct
  private void init() {
    log.info("Init generic security");
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "basic")
  @EnableBasicAuth
  public static class GenericBasicAuthConfiguration {
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "saml2")
  @EnableSaml2
  public static class GenericSaml2Configuration {
  }

  @Configuration
  @Conditional(NoExpectedValuesCondition.class)
  @RequiredArgsConstructor
  public static class GenericMissingMakeLog {
    @Value("${cognizone.security.auth-method:}")
    private final String authenticationMethod;

    @ConditionalOnMissingBean
    @Bean
    public SecurityHttpConfigurer<? extends SecurityHttpConfigurer> securityHttpConfigurer() {
      if (StringUtils.isBlank(authenticationMethod)) throw new RuntimeException("No authentication method specified via property 'cognizone.security.auth-method'.");
      else throw new RuntimeException("Value '" + authenticationMethod + "' of property 'cognizone.security.auth-method' not supported, use one of basic, saml2.");
    }
  }

  public static class NoExpectedValuesCondition extends NoneNestedConditions {

    public NoExpectedValuesCondition() {
      super(ConfigurationPhase.PARSE_CONFIGURATION);
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "basic")
    static class BasicAuthCondition {
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "saml2")
    static class Saml2Condition {
    }

  }

}