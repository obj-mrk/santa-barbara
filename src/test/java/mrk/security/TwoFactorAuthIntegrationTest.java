package mrk.security;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetupTest;
import jakarta.mail.BodyPart;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import mrk.security.user.dto.AuthResponse;
import mrk.security.user.dto.LoginRequest;
import mrk.security.user.dto.LoginStep1Response;
import mrk.security.user.dto.OtpVerifyRequest;
import mrk.security.user.dto.RegisterRequest;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestPropertySource(properties = {
        // Подгоняем Spring Mail под настройки ServerSetupTest.SMTP (localhost:3025)
        "spring.mail.host=localhost",
        "spring.mail.port=3025",
        "spring.mail.properties.mail.smtp.auth=false",
        "spring.mail.properties.mail.smtp.starttls.enable=false"
})
class TwoFactorAuthIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private GreenMail greenMail;

    @BeforeAll
    void setupMail() {
        // Стартуем embedded SMTP-сервер GreenMail
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
    void loginWithEmailOtp_successFlow() throws Exception {
        // ---------- 0. Регистрация пользователя ----------
        String email = "otp-test-" + UUID.randomUUID() + "@example.com";
        String password = "Password123!";
        String name = "Otp User";

        RegisterRequest registerRequest = new RegisterRequest(email, password, name);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.postForEntity(
                url("/register"),
                registerRequest,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(registerResponse.getBody()).isNotNull();
        assertThat(registerResponse.getBody().token()).isNotBlank();

        // ---------- 1. login step 1: логин + пароль ----------
        LoginRequest loginRequest = new LoginRequest(email, password);

        ResponseEntity<LoginStep1Response> step1Response = restTemplate.postForEntity(
                url("/login"),
                loginRequest,
                LoginStep1Response.class
        );

        assertThat(step1Response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(step1Response.getBody()).isNotNull();
        UUID sessionId = step1Response.getBody().session();
        assertThat(sessionId).isNotNull();

        // ---------- 2. Ждём входящее письмо и достаём OTP ----------
        greenMail.waitForIncomingEmail(1);

        Message[] messages = greenMail.getReceivedMessages();
        assertThat(messages).hasSize(1);

        String body = extractBody(messages[0]);

        // 6-значный OTP код
        Pattern pattern = Pattern.compile("(\\d{6})");
        Matcher matcher = pattern.matcher(body);
        assertThat(matcher.find()).isTrue();
        String otpCode = matcher.group(1);

        // ---------- 3. login step 2: sessionId + code ----------
        OtpVerifyRequest otpVerifyRequest = new OtpVerifyRequest(sessionId, otpCode);

        ResponseEntity<AuthResponse> step2Response = restTemplate.postForEntity(
                url("/login/otp"),
                otpVerifyRequest,
                AuthResponse.class
        );

        assertThat(step2Response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(step2Response.getBody()).isNotNull();
        assertThat(step2Response.getBody().token()).isNotBlank();
    }

    private String url(String path) {
        return "http://localhost:" + port + "/api/v1/auth" + path;
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
