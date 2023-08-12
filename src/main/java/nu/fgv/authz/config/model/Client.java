package nu.fgv.authz.config.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class Client {

    private String id;
    private String clientId;
    private String clientSecret;
    private List<String> clientAuthenticationMethods;
    private List<String> authorizationGrantTypes;
    private List<String> redirectUris;
    private List<String> scopes;
    private Map<String, Object> clientSettings;
}
