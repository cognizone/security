package zone.cogni.lib.security.saml2;

import lombok.Data;
import lombok.ToString;
import zone.cogni.lib.security.common.BasicAuthUser;

import java.util.HashMap;
import java.util.Map;

@Data
public class Saml2Properties {

  private SigningKeys signingKeyStore;
  private String registrationId;
  private String entityId;
  private String baseUrl;
  private String idpUrl;
  private String assertionConsumerServiceUrl;
  private Attributes attributes;
  private String roleMappingUrl;
  private Boolean logSamlResponse;
  private Map<String, BasicAuthUser> basicAuthUsers = new HashMap<>(); //init so we allow empty config

  public enum KeyStoreType {JKS}

  @Data
  public static class SigningKeys {
    private KeyStoreType type;
    private String storeUrl;
    @ToString.Exclude
    private String keystorePassword;
    private String alias;
    @ToString.Exclude
    private String certificatePassword;
  }

  @Data
  public static class Attributes {
    private String firstname;
    private String lastname;
    private String displayname;
    private String roles;
    private String loginid;
    private String email;
  }

}
