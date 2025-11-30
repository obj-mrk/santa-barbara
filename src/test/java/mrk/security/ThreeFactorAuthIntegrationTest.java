package mrk.security;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetupTest;
import jakarta.mail.BodyPart;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import mrk.security.user.dto.request.*;
import mrk.security.user.dto.response.AuthResponse;
import mrk.security.user.dto.response.LoginStepResponse;
import mrk.security.user.dto.response.TotpSetupResponse;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Интеграционный тест полного 3FA-флоу:
 *  1) регистрация пользователя;
 *  2) настройка TOTP (setup + confirm) под JWT;
 *  3) login/password -> EMAIL_OTP;
 *  4) login/otp -> TOTP;
 *  5) login/totp -> финальный JWT.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestPropertySource(properties = {
        // Подгоняем Spring Mail под настройки ServerSetupTest.SMTP (localhost:3025)
        "spring.mail.host=localhost",
        "spring.mail.port=3025",
        "spring.mail.properties.mail.smtp.auth=false",
        "spring.mail.properties.mail.smtp.starttls.enable=false"
})
class ThreeFactorAuthIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TimeBasedOneTimePasswordGenerator totpGenerator;

    @Autowired
    private Base32 base32;

    private GreenMail greenMail;

    @BeforeAll
    void setupMail() {
        greenMail = new GreenMail(ServerSetupTest.SMTP);
        greenMail.start();
    }

    @AfterAll
    void stopMail() {
        if (greenMail != null) {
            greenMail.stop();
        }
    }

    @Test
    void fullThreeFactorAuth_successFlow() throws Exception {
        // ---------- 0. Регистрация пользователя ----------
        String email = "3fa-test-" + UUID.randomUUID() + "@example.com";
        String password = "Password123!";
        String name = "3FA User";

        RegisterRequest registerRequest = new RegisterRequest(email, password, name);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.postForEntity(
                url("/register"),
                registerRequest,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(registerResponse.getBody()).isNotNull();
        String registrationJwt = registerResponse.getBody().token();
        assertThat(registrationJwt).isNotBlank();

        // ---------- 1. Настройка TOTP (setup + confirm) ----------
        // 1.1. /totp/setup под JWT
        HttpHeaders setupHeaders = new HttpHeaders();
        setupHeaders.setBearerAuth(registrationJwt);
        HttpEntity<Void> setupRequest = new HttpEntity<>(setupHeaders);

        ResponseEntity<TotpSetupResponse> setupResponse = restTemplate.exchange(
                url("/totp/setup"),
                HttpMethod.POST,
                setupRequest,
                TotpSetupResponse.class
        );

        assertThat(setupResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(setupResponse.getBody()).isNotNull();
        String secret = setupResponse.getBody().secret();
        assertThat(secret).isNotBlank();

        // 1.2. Генерируем валидный TOTP-код по секрету
        String totpCodeForConfirm = generateTotpCode(secret);

        // 1.3. /totp/confirm под тем же JWT
        HttpHeaders confirmHeaders = new HttpHeaders();
        confirmHeaders.setContentType(MediaType.APPLICATION_JSON);
        confirmHeaders.setBearerAuth(registrationJwt);

        TotpVerifyRequest confirmBody = new TotpVerifyRequest(totpCodeForConfirm);
        HttpEntity<TotpVerifyRequest> confirmRequest = new HttpEntity<>(confirmBody, confirmHeaders);

        ResponseEntity<Void> confirmResponse = restTemplate.postForEntity(
                url("/totp/confirm"),
                confirmRequest,
                Void.class
        );

        assertThat(confirmResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        // ---------- 2. login step 1: пароль ----------
        LoginRequest loginRequest = new LoginRequest(email, password);

        ResponseEntity<LoginStepResponse> step1Response = restTemplate.postForEntity(
                url("/login/password"),
                loginRequest,
                LoginStepResponse.class
        );

        assertThat(step1Response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(step1Response.getBody()).isNotNull();
        UUID sessionId = step1Response.getBody().session();
        assertThat(sessionId).isNotNull();
        assertThat(step1Response.getBody().nextFactor()).isEqualTo("EMAIL_OTP");

        // ---------- 3. Получаем email с OTP и достаём код ----------
        greenMail.waitForIncomingEmail(1);

        Message[] messages = greenMail.getReceivedMessages();
        assertThat(messages).hasSize(1);

        String body = extractBody(messages[0]);

        Pattern pattern = Pattern.compile("(\\d{6})");
        Matcher matcher = pattern.matcher(body);
        assertThat(matcher.find()).isTrue();
        String emailOtpCode = matcher.group(1);

        // ---------- 4. login step 2: e-mail OTP ----------
        EmailOtp3faRequest emailOtp3faRequest = new EmailOtp3faRequest(sessionId, emailOtpCode);

        ResponseEntity<LoginStepResponse> step2Response = restTemplate.postForEntity(
                url("/login/otp"),
                emailOtp3faRequest,
                LoginStepResponse.class
        );

        assertThat(step2Response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(step2Response.getBody()).isNotNull();
        assertThat(step2Response.getBody().session()).isEqualTo(sessionId);
        assertThat(step2Response.getBody().nextFactor()).isEqualTo("TOTP");

        // ---------- 5. login step 3: TOTP ----------
        // Генерируем новый актуальный TOTP-код по тому же secret
        String totpCodeForLogin = generateTotpCode(secret);

        Totp3faRequest totp3faRequest = new Totp3faRequest(sessionId, totpCodeForLogin);

        ResponseEntity<AuthResponse> finalResponse = restTemplate.postForEntity(
                url("/login/totp"),
                totp3faRequest,
                AuthResponse.class
        );

        assertThat(finalResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(finalResponse.getBody()).isNotNull();
        assertThat(finalResponse.getBody().token()).isNotBlank();
    }

    private String url(String path) {
        return "http://localhost:" + port + "/api/v1/auth" + path;
    }

    /**
     * Генерация TOTP-кода по секрету в Base32.
     * Логика согласована с TotpService: decodeSecret + generateOneTimePassword.
     */
    private String generateTotpCode(String secretBase32) throws Exception {
        String normalizedSecret = secretBase32.replace(" ", "").toUpperCase();
        byte[] keyBytes = base32.decode(normalizedSecret);
        SecretKey key = new SecretKeySpec(keyBytes, totpGenerator.getAlgorithm());

        int otp = totpGenerator.generateOneTimePassword(key, Instant.now());
        return String.format("%0" + totpGenerator.getPasswordLength() + "d", otp);
    }

    /**
     * Универсальное извлечение текстового тела из письма (plain text или multipart).
     */
    private String extractBody(Message message) throws Exception {
        Object content = message.getContent();

        if (content instanceof String s) {
            return s;
        }
        if (content instanceof Multipart multipart) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);
                Object partContent = part.getContent();
                if (partContent instanceof String ps) {
                    sb.append(ps);
                }
            }
            return sb.toString();
        }
        return content.toString();
    }
}
