package mrk.security.auth;

import lombok.RequiredArgsConstructor;

import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.UserRole;
import mrk.persistence.repo.UserRepository;
import mrk.security.jwt.JwtService;
import mrk.security.user.CustomUserDetails;
import mrk.security.user.dto.AuthResponse;
import mrk.security.user.dto.LoginRequest;
import mrk.security.user.dto.RegisterRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setName(request.name());
        user.setRole(UserRole.USER);
        userRepository.save(user);

        String token = jwtService.generateToken(new CustomUserDetails(user.getId(), user.getEmail(), user.getPassword(), user.getRole()));
        return new AuthResponse(token);
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );
        User user = userRepository.findByEmail(request.email()).orElseThrow();
        String token = jwtService.generateToken(new CustomUserDetails(user.getId(), user.getEmail(), user.getPassword(), user.getRole()));
        return new AuthResponse(token);
    }
}
