# Cognizone Security

## Needed code to make it work
```java
@Configuration
//Use any of the following
//@EnableSaml2
@EnableBasicAuth
//@EnableSecurity
public class WebSecurityConfig {

  //Inject this using your favorite way
  private final SecurityHttpConfigurer<? extends AsquareHttpConfigurer> security2HttpConfigurer;

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
    auth-method: basic # other accepted values are: saml2
```

## Configuration example - SAML2

### Spring Yaml configuration
```yaml
cognizone:
  security:
    saml2:
      logSamlResponse: true # optional, if set to true, logs the saml XML response
      role-mapping-url: classpath:/security/samlRoleMapping-aws.json # Mapping between role defined in SAML server and your application
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
      basic-auth-users: # Optional: configuration to be able to do basic-auth call's (for example for API calls)
        admin:
          password: "{bcrypt}$2a$12$.6Mn9xZi5a1vwCBtH6Yy4ulmoTr8qvoS9tgZTk/UXy/OOwa4r14cG"
          roles:
            - admin
            - view
        user:
          password: "{noop}plainPasswordNotGood"
          roles:
            - view
```
_Note: if basic-auth users are passed, they will only be taken into account if the correct basic-auth header is passed.
If the header is incorrect (no user, wrong password,...), this will just be ignored._
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
