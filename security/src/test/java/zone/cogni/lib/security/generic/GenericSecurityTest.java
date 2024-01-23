package zone.cogni.lib.security.generic;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import zone.cogni.lib.security.DefaultTestController;
import zone.cogni.lib.security.DefaultUserDetails;
import zone.cogni.lib.security.GoSecurityTest;
import zone.cogni.lib.security.generic.impl.UserViaHeaderConfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {DefaultTestController.class, UserViaHeaderConfiguration.class})
@ActiveProfiles("test-generic-auth-1")
class GenericSecurityTest extends GoSecurityTest {

  @Test
  void testViaHeaderOk() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .header("user-id", "jef"))
           .andExpect(status().isOk());

    Authentication authentication = DefaultTestController.authentication;
    assertThat(authentication)
            .isNotNull()
            .extracting(Authentication::getDetails)
            .isInstanceOf(DefaultUserDetails.class)
            .extracting(DefaultUserDetails.class::cast)
            .satisfies(userDetails -> {
              assertThat(userDetails.getUsername()).isEqualTo("jef");
              assertThat(userDetails.getLoginId()).isEqualTo("jef");
              assertThat(userDetails.getDisplayName()).isEqualTo("Jef louis");
              assertThat(userDetails.getEmail()).isEqualTo("jef.louis@mail.com");
            });
    checkRoles("jow");
  }

  @Test
  void testViaHeaderOk_ignoreBasicAuth() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .header("user-id", "jef")
                            .with(httpBasic("admin", "admin")))
           .andExpect(status().isOk());

    Authentication authentication = DefaultTestController.authentication;
    assertThat(authentication)
            .isNotNull()
            .extracting(Authentication::getDetails)
            .isInstanceOf(DefaultUserDetails.class)
            .extracting(DefaultUserDetails.class::cast)
            .satisfies(userDetails -> {
              assertThat(userDetails.getUsername()).isEqualTo("jef");
              assertThat(userDetails.getLoginId()).isEqualTo("jef");
              assertThat(userDetails.getDisplayName()).isEqualTo("Jef louis");
              assertThat(userDetails.getEmail()).isEqualTo("jef.louis@mail.com");
            });
    checkRoles("jow");
  }

  @Test
  void testViaHeaderUnkownUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .header("user-id", "louis"))
           .andExpect(status().isForbidden());
  }

  @Test
  void testViaHeaderNoUser() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication"))
           .andExpect(status().isForbidden());
  }

  @Test
  void testAdminUser_alsoWrongGenericHeader() throws Exception {
    mockMvc.perform(post("/private/rememberAuthentication")
                            .header("user-id", "louis")
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
              assertThat(userDetails.getDisplayName()).isEqualTo("API: anon");
              assertThat(userDetails.getEmail()).isNull();
            });
    checkRoles();
  }
}
