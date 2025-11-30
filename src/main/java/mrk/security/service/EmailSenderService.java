package mrk.security.service;

import lombok.RequiredArgsConstructor;
import mrk.security.config.EmailOtpProperties;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Сервис для отправки email-уведомлений с одноразовыми кодами (OTP)
 * Используется для аутентификации и подтверждения действий пользователя
* */

@Service
@RequiredArgsConstructor
public class EmailSenderService {
    private final JavaMailSender mailSender;
    private final EmailOtpProperties properties;

    /**
     * Отправляет одноразовый код подтверждения (OTP) на указанный email
     * Генерирует письмо с кодом и информацией о времени его действия
     *
     * @param to Email-адрес получателя
     * @param code Одноразовый код подтверждения (6-значный числовой код)
     */

    public void sendOtpCode(String to, String code) {
        SimpleMailMessage message = new SimpleMailMessage();

        // Настройка базовых параметров письма
        message.setFrom(properties.getSender());
        message.setTo(to);
        message.setSubject("Код подтверждения входа");

        // Формирование текста письма с кодом и информацией о времени жизни
        message.setText(
                "Ваш код подтверждения: " + code + "\n\n" +
                        "Код действителен " + properties.getTtlMinutes() + " минут."
        );

        // Отправка письма
        mailSender.send(message);
    }
}