package com.example.backend.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.backend.entity.User;
import com.example.backend.repository.UserRepositroy;

@Service
public class UserService {
	@Autowired
	UserRepositroy userRepository;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	public User registerUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepository.save(user);
	}

	public Optional<User> findByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	public boolean validateCredentials(String email, String rawPassword) {
		Optional<User> userOpt = userRepository.findByEmail(email);
		return userOpt.isPresent() && passwordEncoder.matches(rawPassword, userOpt.get().getPassword());
	}

}
