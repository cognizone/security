package zone.cogni.lib.security.common;

import lombok.Data;

@Data
public class GlobalProperties {

  private final Logout logout = new Logout();

  @Data
  public static class Logout {
    private String url;
    private String successUrl;
  }

}
