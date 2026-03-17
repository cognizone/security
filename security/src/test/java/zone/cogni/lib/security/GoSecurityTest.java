package zone.cogni.lib.security;

import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

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
    DefaultUserDetails userDetails = (DefaultUserDetails) DefaultTestController.authentication.getDetails();
    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

    Collection<String> stringizedList = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    assertThat(stringizedList).hasSize(roles.length)
                              .contains(roles);
  }

}
