package com.example.spring_security.security.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;




import org.springframework.transaction.annotation.Transactional;

import com.example.spring_security.models.User;
import com.example.spring_security.security.repository.UserRepository;
@Service
public class UserService {

	
	private final UserRepository userRepository;
	
	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	
    @Autowired
    private PasswordEncoder passwordEncoder;
	
	public void addUserRole(Long userId, Integer role) {
		// Check the user
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Kullanıcı bulunamadı: " + userId));

        // Check if the user has this role
        if (isUserRoleExists(userId, role)) {
            throw new IllegalStateException("Kullanıcı zaten bu role sahip.");
        }

        // Add data to user_roles table with SQL query
        String sql = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
        jdbcTemplate.update(sql, user.getId(), role);
    }

	public boolean isUserRoleExists(Long userId, Integer roleId) {
        return userRepository.existsByUserIdAndRoleId(userId, roleId);
    }
	
    public Optional<User> findById(Long userId) {
        return userRepository.findById(userId);
    }
    
    
	
	public UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
	
	
	public List<User> getAllUsers() {
		return userRepository.findAll();
	}

	
	public User getOneUserById(Long userId) {
	    return userRepository.findById(userId).orElse(null);
	}

	
	
	public void deleteOneUser(Long userId) {
		// TODO Auto-generated method stub
		userRepository.deleteById(userId);
	}
	
	 @Transactional
	    public boolean changePassword(String username, String newPassword) {
	        Optional<User> userOptional = userRepository.findByUsername(username);

	        if (userOptional.isPresent()) {
	            User user = userOptional.get();
	            String encodedPassword = passwordEncoder.encode(newPassword); // Encode the password
	            user.setPassword(encodedPassword);
	            userRepository.save(user); // Save updated user
	            return true;
	        }

	        return false; // If the user is not found
	    }
	
	
	
	
	
}