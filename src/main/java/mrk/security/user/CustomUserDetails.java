package mrk.security.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import mrk.persistence.entity.enums.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Реализация UserDetails Spring Security для представления аутентифицированного пользователя
 * Адаптирует доменную модель User к требованиям Spring Security
 *
 * Содержит основные данные пользователя, необходимые для аутентификации и авторизации
 *
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CustomUserDetails implements UserDetails {
    private UUID id;
    private String email;
    private String password;
    private UserRole role;

    /**
     * Возвращает список прав (authorities) пользователя на основе его роли
     * Spring Security использует это для проверки доступа к ресурсам
     *
     * @return коллекция прав пользователя с префиксом "ROLE_"
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
