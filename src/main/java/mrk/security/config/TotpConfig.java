package mrk.security.config;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.NoSuchAlgorithmException;

@Configuration
public class TotpConfig {
    @Bean
    public TimeBasedOneTimePasswordGenerator totpGenerator() throws NoSuchAlgorithmException {
        return new TimeBasedOneTimePasswordGenerator();
    }

    @Bean
    public Base32 base32() {
        return new Base32();
    }
}
