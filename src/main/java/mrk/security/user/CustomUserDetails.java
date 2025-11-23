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
     * Флаг блокировки учетной записи
     * Используется для реализации административной блокировки пользователя
     */
    private boolean blocked;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Если пользователь заблокирован администратором, считаем аккаунт "залоченным"
     */
    @Override
    public boolean isAccountNonLocked() {
        return !blocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Аналогично isAccountNonLocked - в простом варианте считаем,
     * что заблокированный пользователь "не включен" в системе
     */
    @Override
    public boolean isEnabled() {
        return !blocked;
    }
}
