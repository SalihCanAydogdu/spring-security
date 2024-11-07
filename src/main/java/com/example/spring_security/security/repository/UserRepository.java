package com.example.spring_security.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.spring_security.models.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
  
  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
  
  //Return only the mail field
  User findById(long id);
  @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u JOIN u.roles r WHERE u.id = :userId AND r.id = :roleId")
  boolean existsByUserIdAndRoleId(@Param("userId") long userId, @Param("roleId") Integer roleId);


  
}
