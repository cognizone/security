package zone.cogni.lib.security;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import javax.inject.Inject;
import java.util.Collection;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@AutoConfigureMockMvc
@ContextConfiguration(classes = EnableSecurityInTestConfiguration.class)
public abstract class GoSecurityTest {
  @Inject
  protected MockMvc mockMvc;

  @BeforeEach
  public void beforeTestMethod() {
    DefaultTestController.authentication = null;
  }

  protected void checkRoles(String... roles) {
    Collection<? extends GrantedAuthority> authorities = DefaultTestController.authentication.getAuthorities();
    DefaultUserDetails userDetails = (DefaultUserDetails) DefaultTestController.authentication.getDetails();
    assertThat(authorities)
            .isEqualTo(userDetails.getAuthorities());

    Collection<String> stringizedList = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    assertThat(stringizedList).hasSize(roles.length)
                              .contains(roles);
  }

}
