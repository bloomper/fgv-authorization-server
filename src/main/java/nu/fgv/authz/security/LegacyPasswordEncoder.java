package nu.fgv.authz.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
@Slf4j
public class LegacyPasswordEncoder implements PasswordEncoder {

    private final Pattern LEGACY_PATTERN = Pattern.compile("\\$(.+)\\$(.+)");

    private final String algorithm;
    private final int numberOfIterations;

    @Override
    public boolean upgradeEncoding(final String encodedPassword) {
        return true;
    }

    @Override
    public String encode(final CharSequence rawPassword) {
        throw new IllegalStateException("Legacy password encoding must not be used");
    }

    @Override
    public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Raw password cannot be null");
        }
        if (encodedPassword == null || encodedPassword.isEmpty()) {
            log.warn("Empty encoded password");
            return false;
        }
        if (!LEGACY_PATTERN.matcher(encodedPassword).matches()) {
            log.warn("Encoded password does not look like it is a legacy password");
            return false;
        }
        try {
            final Matcher matcher = LEGACY_PATTERN.matcher(encodedPassword);
            final String salt = matcher.group(1);
            final String cryptedPassword = matcher.group(2);
            final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            String digest = String.format("%s%s", rawPassword, salt);

            for (int i = 0; i < numberOfIterations; i++) {
                digest = encodePassword(messageDigest, digest);
            }

            return digest.equals(cryptedPassword);
        } catch (final NoSuchAlgorithmException e) {
            log.error("Unknown algorithm {} specified", algorithm, e);
            throw new IllegalArgumentException(e);
        }
    }

    private String encodePassword(final MessageDigest messageDigest, final String password) {
        return bytesToHex(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
    }

    private static String bytesToHex(byte[] hash) {
        final StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (byte b : hash) {
            final String hex = Integer.toHexString(0xff & b);

            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
