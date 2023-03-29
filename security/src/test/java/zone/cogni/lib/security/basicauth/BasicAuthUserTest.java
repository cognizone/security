package zone.cogni.lib.security.basicauth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import zone.cogni.lib.security.BasicActionsTestController;
import zone.cogni.lib.security.GoSecurityTest;
import zone.cogni.lib.security.DefaultUserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = BasicActionsTestController.class)
@ActiveProfiles("test-basic-auth-1")
public class BasicAuthUserTest extends GoSecurityTest {

  @Test
  public void testAdminUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .with(httpBasic("admin", "admin")))
           .andExpect(status().isOk());

    assertThat(BasicActionsTestController.authentication)
            .isNotNull()
            .extracting(Authentication::getDetails)
            .isInstanceOf(DefaultUserDetails.class)
            .extracting(DefaultUserDetails.class::cast)
            .satisfies(userDetails -> {
              assertThat(userDetails.getUsername()).isEqualTo("admin");
              assertThat(userDetails.getLoginId()).isEqualTo("admin");
              assertThat(userDetails.getDisplayName()).isEqualTo("el adminos");
              assertThat(userDetails.getEmail()).isEqualTo("mail@admin.com");
            });
    checkRoles("admin", "batman");
    checkRoles("batman", "admin");
  }

  @Test
  public void testAnonUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .with(httpBasic("anon", "zopzop")))
           .andExpect(status().isOk());

    assertThat(BasicActionsTestController.authentication)
            .isNotNull()
            .extracting(Authentication::getDetails)
            .isInstanceOf(DefaultUserDetails.class)
            .extracting(DefaultUserDetails.class::cast)
            .satisfies(userDetails -> {
              assertThat(userDetails.getUsername()).isEqualTo("anon");
              assertThat(userDetails.getLoginId()).isEqualTo("anon");
              assertThat(userDetails.getDisplayName()).isNull();
              assertThat(userDetails.getEmail()).isNull();
            });
    checkRoles();
  }

  private void checkRoles(String... roles) {
    Collection<? extends GrantedAuthority> authorities = BasicActionsTestController.authentication.getAuthorities();
    DefaultUserDetails userDetails = (DefaultUserDetails) BasicActionsTestController.authentication.getDetails();
    assertThat(authorities)
            .isEqualTo(userDetails.getAuthorities());

    Collection<String> stringizedList = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    assertThat(stringizedList).hasSize(roles.length)
                              .contains(roles);
  }
}
