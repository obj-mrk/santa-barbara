package mrk.security.admin;

import lombok.RequiredArgsConstructor;
import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.UserRole;
import mrk.persistence.repo.UserRepository;
import mrk.security.user.dto.response.AdminUserResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Сервис для административных операций над пользователями:
 * - отображение списка пользователей;
 * - изменение ролей;
 * - блокировка/разблокировка.
 */
@Service
@RequiredArgsConstructor
@Transactional
public class AdminUserService {

    private final UserRepository userRepository;

    /**
     * Возвращает список всех пользователей в системе.
     * В реальном приложении здесь лучше добавить пагинацию и фильтры.
     */
    @Transactional(readOnly = true)
    public List<AdminUserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    /**
     * Изменение роли пользователя.
     *
     * Ограничения:
     * - администратор не может понизить собственную роль;
     * - нельзя лишить систему последнего ADMIN.
     */
    public AdminUserResponse changeUserRole(UUID userId, UserRole newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        UUID currentAdminId = getCurrentUserId();

        // Запрещаем понижать/менять свою роль
        if (user.getId().equals(currentAdminId)) {
            throw new IllegalStateException("Нельзя изменять собственную роль");
        }

        // Если понижаем администратора, проверим, что он не последний
        if (user.getRole() == UserRole.ADMIN && newRole != UserRole.ADMIN) {
            long adminsCount = userRepository.countByRole(UserRole.ADMIN);
            if (adminsCount <= 1) {
                throw new IllegalStateException("Нельзя понизить последнего администратора");
            }
        }

        user.setRole(newRole);
        userRepository.save(user);

        return toResponse(user);
    }

    /**
     * Блокировка или разблокировка пользователя.
     *
     * Ограничения:
     * - администратор не может заблокировать самого себя;
     * - опционально можно запретить блокировку других администраторов.
     */
    public AdminUserResponse changeUserBlockStatus(UUID userId, boolean blocked) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        UUID currentAdminId = getCurrentUserId();

        if (user.getId().equals(currentAdminId)) {
            throw new IllegalStateException("Нельзя блокировать собственную учетную запись");
        }

        // Если не хочешь позволять блокировать админов — раскомментируй:
        // if (user.getRole() == UserRole.ADMIN) {
        //     throw new IllegalStateException("Нельзя блокировать администратора");
        // }

        user.setBlocked(blocked);
        userRepository.save(user);

        return toResponse(user);
    }

    private AdminUserResponse toResponse(User user) {
        return new AdminUserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRole(),
                user.isEmailVerified(),
                user.isBlocked(),
                user.getCreatedAt()
        );
    }

    /**
     * Утилитарный метод для получения id текущего аутентифицированного пользователя
     * из SecurityContext (ожидаем, что principal – это CustomUserDetails).
     */
    private UUID getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        if (principal instanceof mrk.security.user.CustomUserDetails cud) {
            return cud.getId();
        }
        throw new IllegalStateException("Не удалось определить текущего пользователя");
    }
}
