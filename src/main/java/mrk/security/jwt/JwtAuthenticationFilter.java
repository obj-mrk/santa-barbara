package mrk.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import mrk.security.user.CustomUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Фильтр Spring Security для JWT аутентификации
 * Обрабатывает каждый HTTP запрос и устанавливает контекст безопасности если предоставлен валидный JWT токен
 *
 * Наследуется от OncePerRequestFilter для гарантии однократного выполнения на запрос
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    /**
     * Основной метод фильтрации запросов
     * Извлекает JWT токен из заголовка Authorization, проверяет его и устанавливает аутентификацию в SecurityContext
     *
     * @param request HTTP запрос
     * @param response HTTP ответ
     * @param filterChain цепочка фильтров для продолжения обработки
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Извлечение заголовка Authorization
        final String authHeader = request.getHeader("Authorization");

        // Пропускаем запрос дальше если заголовок отсутствует или не в формате Bearer
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Извлечение токена из заголовка (убираем "Bearer ")
        String token = authHeader.substring(7);

        // Извлечение username (email) из токена
        String username = jwtService.extractUsername(token);

        // Если username извлечен и пользователь еще не аутентифицирован в текущем контексте
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Загрузка данных пользователя из базы данных
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Проверка валидности токена
            if (jwtService.isTokenValid(token, userDetails)
                    && userDetails.isAccountNonLocked()
                    && userDetails.isEnabled()) {
                // Создание объекта аутентификации Spring Security
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Добавление дополнительных деталей запроса
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Установка аутентификации в контекст безопасности
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        // Продолжение обработки запроса следующими фильтрами
        filterChain.doFilter(request, response);
    }
}
