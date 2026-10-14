package com.uday.finpulse.controller;

import com.uday.finpulse.entity.Company;
import com.uday.finpulse.repository.CompanyRepository;
import com.uday.finpulse.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final CompanyRepository companyRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(CompanyRepository companyRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil) {
        this.companyRepository = companyRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public record RegisterRequest(String companyName, String email, String password) {}
    public record LoginRequest(String email, String password) {}

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (companyRepository.findByEmail(request.email()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }
        Company company = new Company();
        company.setCompanyName(request.companyName());
        company.setEmail(request.email());
        company.setPassword(passwordEncoder.encode(request.password()));
        Company saved = companyRepository.save(company);
        return ResponseEntity.ok(Map.of("id", saved.getId(), "email", saved.getEmail()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return companyRepository.findByEmail(request.email())
                .filter(c -> passwordEncoder.matches(request.password(), c.getPassword()))
                .<ResponseEntity<?>>map(c -> ResponseEntity.ok(
                        Map.of("token", jwtUtil.generateToken(c.getId(), c.getEmail()))))
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(Map.of("error", "Invalid credentials")));
    }
}
