package com.example.backend.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.backend.entity.User;
import com.example.backend.security.JwtUtil;
import com.example.backend.service.UserService;

import lombok.Data;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins="http://localhost:5173")
public class AuthController {
	
	
	@Autowired
	UserService userService;

	@Autowired
	JwtUtil jwtUtil;
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest request) {
		boolean valid = userService.validateCredentials(request.getEmail(), request.getPassword());

		if (!valid) {
			return ResponseEntity.status(401).body("Invalid Credentials");
		}

		User user = userService.findByEmail(request.getEmail()).get();
		Map<String, Object> claims = new HashMap<>();
		claims.put("role", user.getRole());
		String token = jwtUtil.generateTokens(request.getEmail(), claims);
		Map<String, Object> response = new HashMap<>();
		response.put("token", token);
		response.put("name", user.getName());
		response.put("role", user.getRole());
		response.put("id", user.getId());
		return ResponseEntity.ok(response);
	}
	
	@PostMapping("/signup")
	public ResponseEntity<Map<String, String>> register(@RequestBody SignupRequest request) {
		User user = User.builder()
				.name(request.getName())
				.email(request.getEmail())
				.password(request.getPassword())
				.role(request.getRole())
				.build();
		userService.registerUser(user);
		Map<String, String> response = new HashMap<>();
		response.put("message", "User registered successfully");
		
		return ResponseEntity.ok(response);
	}
	
	
	@Data
	public static class SignupRequest{
		private String name;
		private String email;
		private String password;
		private String role;
	}
	
	@Data
		public static class LoginRequest{
			private String email;
			private String password;
		}
}
