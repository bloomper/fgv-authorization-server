package nu.fgv.authz.config.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class PasswordEncoding {

    private Map<String, Object> settings;
}
