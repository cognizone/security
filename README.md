# Cognizone Security

## Needed code to make it work
```java
@Configuration
//Use any of the following
//@EnableSecuritySaml2
@EnableSecureBasicAuth
//@EnableSecurityOff
//@EnableSecurity
public class WebSecurityConfig {

  //Inject this using your favorite way
  private final SecurityHttpConfigurer<? extends SecurityHttpConfigurer> security2HttpConfigurer;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.apply(security2HttpConfigurer) //this is the only mandatory part
        
        //Example of extra configuration
        .and()
        //configure what we can access freely and what needs authentication
        .authorizeRequests()
        .mvcMatchers("/user/info").permitAll() //user info page is free
        .anyRequest().authenticated();  //all rest needs authentication
    return http.build();
  }
}
```
Beside the auth type passed via the Enable annotation, no other code needs to be changed. Everything will be set via configuration.

Using `@EnableSecurity`, the auth type selection is done via configuration, so no code change needed if auth type changes.

## Configuration for type selection with `@EnableSecurity`
```yaml
cognizone:
  security:
    auth-method: basic # other accepted values are: saml2, off
```

## Configuration example - SAML2

### Spring Yaml configuration
```yaml
cognizone:
  security:
    saml2:
      logSamlResponse: true # optional, if set to true, logs the saml XML response
      role-mapping-url: classpath:/security/samlRoleMapping-aws.json # Mapping between role defined in SAML server and your application
      baseUrl: https://myserv.com/myAppContext  #optional baseURL of you application (useful in case the infra has some intermediate proxies and spring cannot correctly find the real external URL) 
      assertionConsumerServiceUrl: https://myapp.myserver.com/someapp/saml/SSO   # optional: for example in case you want to reuse the configuration from another saml implementation  
      signing-key-store: # Information to get application certificate registered in SAML server 
        type: jks    # At the moment only JKS is supported
        store-url: classpath:/security/saml-signing.jks
        keystore-password: '********'
        alias: key-alias-in-JKS-file
        certificate-password: '********'
      idp-url: classpath:/security/keycloak-aws-cz.xml  # Info from your SAML server 
      attributes: # Keys of the user medata from SAML - Depending on you SAML server configuration 
        loginid: urn:oid:2.5.4.45
        firstname: urn:oid:2.5.4.42
        lastname: urn:oid:2.5.4.4
        displayname: displayName
        roles: urn:oid:2.5.4.72
        email: urn:oid:1.2.840.113549.1.9.1
      registration-id: myApplication # Registration ID, used to register the application in SAML 
      entity-id: "urn:test.server.com:sp:MyApplication" # Entity ID (can be templated), optional and defaults to "{baseUrl}/saml2/service-provider-metadata/{registrationId}"
      basic-auth-users: # Optional: configuration to be able to do basic-auth call's (for example for API calls)
        admin:
          password: "{bcrypt}$2a$12$.6Mn9xZi5a1vwCBtH6Yy4ulmoTr8qvoS9tgZTk/UXy/OOwa4r14cG"
          displayName: "el adminos" # optional values which can be used as displayName
          email: "mail@admin.com"   # optional 
          roles:
            - admin
            - view
        user:
          password: "{noop}plainPasswordNotGood"
          roles:
            - view
```
_Note1: if **basic-auth** users are passed, they will only be taken into account if the correct basic-auth header is passed.
If the header is incorrect (no user, wrong password,...), this will just be ignored._

_Note2: if you want to use **{registrationId}** in your **assertionConsumerServiceUrl**, 
this has to be at the end of the url and as a separate path part._
### JSON role mapping file example
```json
{
  "saml-admin-role": "application-admin",
  "saml-view-role": "application-user"
}
```

## Configuration example - BasicAuthentication

### Minimal example
```yaml
cognizone:
   security:
      basic-auth:
         users:
            admin:
               password: "{bcrypt}$2a$12$.6Mn9xZi5a1vwCBtH6Yy4ulmoTr8qvoS9tgZTk/UXy/OOwa4r14cG"
```
### Complete example
```yaml
cognizone:
  security:
    basic-auth:
      realm: Hanami is asking who you are  #Realm is optional
      users:
        admin:
          password: "{bcrypt}$2a$12$.6Mn9xZi5a1vwCBtH6Yy4ulmoTr8qvoS9tgZTk/UXy/OOwa4r14cG"
          roles:  #roles are optional
             - admin
             - view
        jef:
          password: "{noop}plainPasswordOfJef"
          roles:  #roles are optional
            - view
```
## Password encryption
For validation of encrypted passwords in the config files the default `"DelegatingPasswordEncoder"` of spring is used. So different encodings can be used. More information can be found here:
- https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html#authentication-password-storage-dpe
- https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/factory/PasswordEncoderFactories.html

In the configuration examples, the bcrypt encoded passwords represent plain password "_admin_". 

## Configure Logout
```yaml
cognizone:
  security:
    global-properties:
      logout:
        url: /api/logout    # URL to use to trigger logout, 
        success-url: https://www.gruutemet.be/  # [OPTIONAL] URL to go to after successful logout (logout URL has to be set)
```

## User details
The method `getDetails()` on `org.springframework.security.core.Authentication` will return a `zone.cogni.lib.security.DefaultUserDetails` object.
This object contains data like displayName and email (if available ofc).

## PermissionService
To enable just add this config:
````yaml
cognizone:
  security:
    permission-service:
      enabled: true
      roleAccess: classpath:security/rolesAccess.json
````
Beside that an enum with the permissions needs to be created in this package/class: `zone.cogni.lib.security.permission.Permission`
```java
package zone.cogni.lib.security.permission;

public enum Permission {
  mainPage_requestTransformation_isEnabled,
  navigation_admin_isEnabled
}
```
After that, the PermissionService will be available to Inject in any service. 
Also the annotation @HasPermission can be used to check the permissions in the Controller classes.

_Note1: if you want to use permission strings with special characters, you can make the Permission enum implement PermissionValue.
When using string, this will match the enum name and the getValue() from PermissionValue._
```java
public enum Permission implements PermissionValue {
  navigation_admin_isEnabled("navigation/admin:isEnabled");

  private final String value;

  Permission(String value) {
    this.value = value;
  }

  @Override
  public String getValue() {
    return value;
  }
}
```
_Note2: You can mix the usage of Permission enum and String values. 
Also, not all String values need to be represented by a Permission enum._ 
