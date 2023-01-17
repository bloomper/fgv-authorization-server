package nu.fgv.register.config;

import nu.fgv.register.security.FederatedIdentityConfigurer;
import nu.fgv.register.security.UserRepositoryOAuth2UserHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
        final FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer()
                .oauth2UserHandler(new UserRepositoryOAuth2UserHandler());

        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .apply(federatedIdentityConfigurer);

        return http.build();
    }

    @Bean
    public UserDetailsService users() {
        final UserDetails user = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
