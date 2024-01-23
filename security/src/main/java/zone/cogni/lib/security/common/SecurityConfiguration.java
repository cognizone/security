package zone.cogni.lib.security.common;

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
import zone.cogni.lib.security.SecurityHttpConfigurer;
import zone.cogni.lib.security.basicauth.EnableSecurityBasicAuth;
import zone.cogni.lib.security.generic.EnableSecurityGeneric;
import zone.cogni.lib.security.off.EnableSecurityOff;
import zone.cogni.lib.security.saml2.EnableSecuritySaml2;

import javax.annotation.PostConstruct;

@Configuration
@Slf4j
public class SecurityConfiguration {

  @PostConstruct
  private void init() {
    log.info("Init generic security");
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "basic")
  @EnableSecurityBasicAuth
  public static class GenericBasicAuthConfiguration {
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "saml2")
  @EnableSecuritySaml2
  public static class GenericSaml2Configuration {
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "generic")
  @EnableSecurityGeneric
  public static class GenericGenericConfiguration {
  }

  @Configuration
  @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "off")
  @EnableSecurityOff
  public static class GenericOffConfiguration {
  }

  @Configuration
  @Conditional(NoExpectedValuesCondition.class) //if we match, it means no or wrong auth-method is passed
  @RequiredArgsConstructor
  public static class GenericMissingMakeLog {
    @Value("${cognizone.security.auth-method:}")
    private final String authenticationMethod;

    @ConditionalOnMissingBean
    @Bean
    public SecurityHttpConfigurer<? extends SecurityHttpConfigurer> securityHttpConfigurer() {
      if (StringUtils.isBlank(authenticationMethod)) throw new RuntimeException("No authentication method specified via property 'cognizone.security.auth-method'.");
      else throw new RuntimeException("Value '" + authenticationMethod + "' of property 'cognizone.security.auth-method' not supported, use one of basic, saml2, generic or off");
    }
  }

  public static class NoExpectedValuesCondition extends NoneNestedConditions { //this condition will match if no Conditions specified in the class match

    public NoExpectedValuesCondition() {
      super(ConfigurationPhase.PARSE_CONFIGURATION);
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "basic")
    static class BasicAuthCondition {
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "saml2")
    static class Saml2Condition {
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "generic")
    static class GenericCondition {
    }

    @ConditionalOnProperty(name = "cognizone.security.auth-method", havingValue = "off")
    static class OffCondition {
    }

  }

}