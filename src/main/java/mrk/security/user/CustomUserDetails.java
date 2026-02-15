package mrk.security.user;

import lombok.Data;
import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Реализация UserDetails Spring Security для представления аутентифицированного пользователя.
 * Адаптирует доменную модель User к требованиям Spring Security.
 *
 * Для создания экземпляров используется статический фабричный метод fromUser(User),
 * который инкапсулирует логику преобразования из доменной сущности.
 */
@Data
public class CustomUserDetails implements UserDetails {

    private UUID id;
    private String email;
    private String password;
    private UserRole role;

    /**
     * Флаг блокировки учетной записи.
     * Используется для реализации административной блокировки пользователя.
     */
    private boolean blocked;

    /**
     * Приватный конструктор. Доступ к созданию объектов осуществляется
     * через фабричный метод fromUser.
     */
    private CustomUserDetails(UUID id,
                              String email,
                              String password,
                              UserRole role,
                              boolean blocked) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.role = role;
        this.blocked = blocked;
    }

    /**
     * Фабричный метод для создания CustomUserDetails на основе доменной модели User.
     * Инкапсулирует маппинг полей и избавляет от дублирования кода во внешних классах.
     *
     * @param user доменная сущность пользователя
     * @return настроенный экземпляр CustomUserDetails
     */
    public static CustomUserDetails fromUser(User user) {
        return new CustomUserDetails(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                user.getRole(),
                user.isBlocked()
        );
    }

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
     * Если пользователь заблокирован администратором, считаем аккаунт "залоченным".
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
     * Аналогично isAccountNonLocked — в простом варианте считаем,
     * что заблокированный пользователь "не включен" в системе.
     */
    @Override
    public boolean isEnabled() {
        return !blocked;
    }
}
