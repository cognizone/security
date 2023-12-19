package zone.cogni.lib.security.basicauth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import zone.cogni.lib.security.DefaultTestController;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.GoSecurityTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = DefaultTestController.class)
@ActiveProfiles("test-basic-auth-1")
class BasicAuthUserTest extends GoSecurityTest {

  @Test
  void testAdminUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .with(httpBasic("admin", "admin")))
           .andExpect(status().isOk());

    assertThat(DefaultTestController.authentication)
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
  void testAnonUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .with(httpBasic("anon", "zopzop")))
           .andExpect(status().isOk());

    assertThat(DefaultTestController.authentication)
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

}
