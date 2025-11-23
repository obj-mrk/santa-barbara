package mrk.security.admin.dto;

import jakarta.validation.constraints.NotNull;
import mrk.persistence.entity.enums.UserRole;

public record ChangeUserRoleRequest(@NotNull UserRole role) {
}