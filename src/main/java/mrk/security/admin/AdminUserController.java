package mrk.security.admin;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import mrk.security.admin.dto.AdminUserResponse;
import mrk.security.admin.dto.ChangeUserBlockRequest;
import mrk.security.admin.dto.ChangeUserRoleRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST-контроллер для административных операций с пользователями.
 *
 * Все маршруты защищены на уровне SecurityConfig:
 * /api/v1/admin/** доступен только пользователям с ролью ADMIN.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;

    /**
     * Получение списка всех пользователей.
     * В дальнейшем можно добавить параметры пагинации / фильтрации.
     */
    @GetMapping
    public ResponseEntity<List<AdminUserResponse>> listUsers() {
        return ResponseEntity.ok(adminUserService.getAllUsers());
    }

    /**
     * Изменение роли пользователя.
     *
     * @param userId  идентификатор пользователя
     * @param request DTO с новой ролью
     */
    @PatchMapping("/{userId}/role")
    public ResponseEntity<AdminUserResponse> changeRole(
            @PathVariable UUID userId,
            @Valid @RequestBody ChangeUserRoleRequest request
    ) {
        AdminUserResponse response = adminUserService.changeUserRole(userId, request.role());
        return ResponseEntity.ok(response);
    }

    /**
     * Блокировка/разблокировка учетной записи пользователя.
     *
     * @param userId  идентификатор пользователя
     * @param request DTO с новым состоянием blocked
     */
    @PatchMapping("/{userId}/block")
    public ResponseEntity<AdminUserResponse> changeBlockStatus(
            @PathVariable UUID userId,
            @Valid @RequestBody ChangeUserBlockRequest request
    ) {
        AdminUserResponse response = adminUserService.changeUserBlockStatus(userId, request.blocked());
        return ResponseEntity.ok(response);
    }
}
