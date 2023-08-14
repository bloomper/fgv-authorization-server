package nu.fgv.authz.config;

import lombok.RequiredArgsConstructor;
import nu.fgv.authz.security.LegacyPasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final FgvConfig fgvConfig;
    private final UserDetailsService userDetailsService;
    private final UserDetailsPasswordService userDetailsPasswordService;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/error", "/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .permitAll()
                );
        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public PasswordEncoder delegatingPasswordEncoder() {
        final Map<String, PasswordEncoder> encoders = new HashMap<>();
        final PasswordEncodersHolder holder = new PasswordEncodersHolder(fgvConfig);

        encoders.put(fgvConfig.getDefaultPasswordEncoderPrefix(), holder.defaultPasswordEncoder());
        encoders.put(fgvConfig.getLegacyPasswordEncoderPrefix(), holder.legacyPasswordEncoder());

        return new DelegatingPasswordEncoder(fgvConfig.getDefaultPasswordEncoderPrefix(), encoders);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setPasswordEncoder(delegatingPasswordEncoder());
        provider.setUserDetailsPasswordService(this.userDetailsPasswordService);
        provider.setUserDetailsService(this.userDetailsService);

        return provider;
    }

    // Workaround as there must only be one password encoder bean
    @RequiredArgsConstructor
    public static final class PasswordEncodersHolder {

        private final FgvConfig fgvConfig;

        public PasswordEncoder defaultPasswordEncoder() {
            return new BCryptPasswordEncoder((int) fgvConfig.getPasswordEncodings().get("bcrypt").getSettings().get("strength"), new SecureRandom());
        }

        public PasswordEncoder legacyPasswordEncoder() {
            return new LegacyPasswordEncoder(
                    (String) fgvConfig.getPasswordEncodings().get("legacy").getSettings().get("algorithm"),
                    (int) fgvConfig.getPasswordEncodings().get("legacy").getSettings().get("number-of-iterations")
            );
        }
    }
}
