package mrk.security.user.dto.request;

import jakarta.validation.constraints.NotNull;
import mrk.persistence.entity.enums.UserRole;

public record ChangeUserRoleRequest(@NotNull UserRole role) {
}