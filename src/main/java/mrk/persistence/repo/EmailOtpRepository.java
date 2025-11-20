package mrk.persistence.repo;

import mrk.persistence.entity.EmailOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface EmailOtpRepository extends JpaRepository<EmailOtp, UUID> {
    Optional<EmailOtp> findTopBySessionIdAndConsumedFalseOrderByCreatedAtDesc(UUID sessionId);
}
