package zone.cogni.lib.security.basicauth;

import lombok.Data;
import zone.cogni.lib.security.common.BasicAuthUser;

import java.util.HashMap;
import java.util.Map;

@Data
public class BasicAuthProperties {

  private String realm;
  private Map<String, BasicAuthUser> users = new HashMap<>(); //init so we allow empty config

}
