package com.pki.example.repo;

import com.pki.example.model.Role;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    User findOneByUsername(String username);
    User findByActivationCode(String activationCode);
    User findByUsernameAndPassword(String username, String password);
    Boolean existsByUsername(String username);
    User findById(int id);

    @Query("SELECT DISTINCT u.roles FROM User u WHERE u = :user")
    List<Role> findDistinctRolesByUser(@Param("user") User user);

}
