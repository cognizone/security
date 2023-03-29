package zone.cogni.lib.security;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import javax.inject.Inject;

@AutoConfigureMockMvc
@ContextConfiguration(classes = EnableSecurityInTestConfiguration.class)
public abstract class GoSecurityTest {
  @Inject
  protected MockMvc mockMvc;

  @BeforeEach
  public void beforeTestMethod() {
    BasicActionsTestController.authentication = null;
  }
}
