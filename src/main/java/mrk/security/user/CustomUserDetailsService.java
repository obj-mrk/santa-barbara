package mrk.security.user;

import lombok.RequiredArgsConstructor;
import mrk.persistence.entity.User;
import mrk.persistence.repo.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Сервис для загрузки данных пользователя в Spring Security
 * Реализует интерфейс UserDetailsService для интеграции с механизмом аутентификации
 *
 * Преобразует данные из доменной модели User в CustomUserDetails для Spring Security
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /**
     * Загружает данные пользователя по email (username)
     * Используется Spring Security во время процесса аутентификации
     *
     * @param email адрес электронной почты пользователя
     * @return UserDetails с данными пользователя для Spring Security
     * @throws UsernameNotFoundException если пользователь с указанным email не найден
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        // Преобразование доменной модели в объект Spring Security
        return new CustomUserDetails(user.getId(), user.getEmail(), user.getPassword(), user.getRole());
    }
}
