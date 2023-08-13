package nu.fgv.authz.security;

import lombok.RequiredArgsConstructor;
import nu.fgv.authz.user.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class CustomUserDetailsPasswordService implements UserDetailsPasswordService {

    private final UserRepository userRepository;

    @Override
    public UserDetails updatePassword(final UserDetails user, final String newPassword) {
        return userRepository
                .findByUid(user.getUsername())
                .map(u -> {
                    u.setPassword(newPassword);
                    return userRepository.save(u);
                })
                .map(CustomUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
