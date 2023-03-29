package zone.cogni.lib.security;

import org.junit.jupiter.api.Assertions;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class BasicActionsTestController {

  public static Authentication authentication;
  
  @RequestMapping("/private/rememberAuthentication")
  @ResponseBody
  public String rememberAuthentication(Authentication authentication) {
    Assertions.assertNull(BasicActionsTestController.authentication, "Authentication object is not null, so multiple calls to this method done without cleanup");
    BasicActionsTestController.authentication = authentication;
    return "OK";
  }
}
