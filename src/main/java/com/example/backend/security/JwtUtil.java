package com.example.backend.security;

import java.security.Key;
import java.util.Date;
import java.util.Map;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	
	private static final String SECRET = "my-secret-test-213456789-fewmorecharacter";
	private static final long EXPIRATION_MS = 24*60*60*1000;
	
	private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes()); 
	
	
	public String generateTokens(String subject, Map<String, Object> claims) {
		
		return Jwts.builder().setClaims(claims)
				.setSubject(subject)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
				.signWith(key, SignatureAlgorithm.HS256)
				.compact();
	}
	
	public Claims extractAllClaims(String tokens) {
		return Jwts.parser().setSigningKey(key)
				.build().parseClaimsJws(tokens).getBody();
	}
	
	public String extractUsername(String tokens) {
		return extractAllClaims(tokens).getSubject();
	}
	
	public boolean isTokenValid(String token) {
		try {
		Claims claims = extractAllClaims(token);
		return claims.getExpiration().before(new Date());
		} catch(Exception e) {
			return false;
		}
	}
}
