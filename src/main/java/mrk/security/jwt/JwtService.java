package mrk.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

/**
 * Сервис для работы с JWT (JSON Web Token) токенами
 * Обеспечивает создание, проверку и извлечение данных из JWT токенов
 *
 * Использует HMAC-SHA алгоритм для подписи токенов
 */
@Service
@RequiredArgsConstructor
public class JwtService {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    /**
     * Генерирует JWT токен для пользователя
     * Включает в токен: subject (email), дату выпуска и дату истечения
     *
     * @param userDetails данные пользователя для включения в токен
     * @return подписанный JWT токен в виде строки
     */
    public String generateToken(UserDetails userDetails) {
        String userEmail = userDetails.getUsername(); // email пользователя
        Date currentDate = new Date(); // время создания
        Date expirationDate = new Date(System.currentTimeMillis() + jwtExpirationMs); // время истечения
        
        return Jwts.builder()
                .setSubject(userEmail) 
                .setIssuedAt(currentDate) 
                .setExpiration(expirationDate) 
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // подпись
                .compact();
    }

    /**
     * Проверяет валидность JWT токена для конкретного пользователя
     *
     * @param token JWT токен для проверки
     * @param userDetails данные пользователя для сравнения
     * @return true если токен валиден и соответствует пользователю
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String tokenUsername = extractUsername(token);
        boolean isUsernameMatching = tokenUsername.equals(userDetails.getUsername());
        boolean isTokenNotExpired = !isExpired(token);
        
        return isUsernameMatching && isTokenNotExpired;
    }

    /**
     * Проверяет истек ли срок действия JWT токена
     *
     * @param token JWT токен для проверки
     * @return true если токен просроченд
     */
    private boolean isExpired(String token) {
        Date exp = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return exp.before(new Date());
    }

    /**
     * Извлекает email пользователя из JWT токена
     *
     * @param token JWT токен
     * @return email пользователя (subject токена)
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Создает ключ для подписи на основе секретной строки
     * Используется для подписи и проверки JWT токенов
     *
     * @return Key объект для работы с JWT
     */
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }
}