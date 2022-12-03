package zone.cogni.asquare.security2.basicauth;

import lombok.Data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class BasicAuthProperties {

  private String realm;
  private Map<String, User> users = new HashMap<>(); //init so we allow empty config

  @Data
  public static class User {
    private String password;
    private List<String> roles = new ArrayList<>(); //init so we allow empty config
  }

}
