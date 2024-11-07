package com.example.spring_security.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.spring_security.models.ERole;
import com.example.spring_security.models.Role;


@Repository
public interface RoleRepository extends JpaRepository<Role,Long>{
	  Optional<Role> findByName(ERole name);
}
