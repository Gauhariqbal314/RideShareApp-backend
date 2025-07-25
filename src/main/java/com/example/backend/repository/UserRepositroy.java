package com.example.backend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.backend.entity.User;

public interface UserRepositroy extends JpaRepository<User, Long> {
	Optional<User> findByEmail(String email);

}
