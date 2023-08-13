package nu.fgv.authz.config;

import lombok.Getter;
import lombok.Setter;
import nu.fgv.authz.config.model.Client;
import nu.fgv.authz.config.model.PasswordEncoding;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "fgv")
@Getter
@Setter
public class FgvConfig {

    private String defaultPasswordEncoderPrefix;
    private String legacyPasswordEncoderPrefix;
    private Map<String, PasswordEncoding> passwordEncodings;
    private Map<String, Client> clients;

    FgvConfig() {
        this.passwordEncodings = new HashMap<>();
        this.clients = new HashMap<>();
    }

}
