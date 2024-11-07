package com.example.spring_security.payload.responses;

import java.util.Set;

import com.example.spring_security.models.Role;
import com.example.spring_security.models.User;
public class UserResponse {

	private Long id;
	private String username;
	private String email;
	private Set<Role> roles;
	
	public UserResponse(User user) {
		this.id = user.getId();
		this.username = user.getUsername();		
		this.email = user.getEmail();
		this.roles = user.getRoles();
	}
	
	
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public Set<Role> getRoles() {
		return roles;
	}
	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}
	
	
}