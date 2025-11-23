package mrk.persistence.repo;

import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);

    /**
     * Подсчет количества пользователей по роли.
     * Используется для предотвращения удаления/понижения последнего администратора.
     */
    long countByRole(UserRole role);
}
