package com.pki.example.repo;

import com.pki.example.model.Role;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    User findOneByUsername(String username);
    User findByActivationCode(String activationCode);
    User findByUsernameAndPassword(String username, String password);
    Boolean existsByUsername(String username);
    User findById(int id);

    @Query("SELECT DISTINCT u.roles FROM User u WHERE u = :user")
    List<Role> findDistinctRolesByUser(@Param("user") User user);

    List<User> findAllByFirstname(String name);

    @Query("SELECT DISTINCT u FROM User u WHERE u.lastname = :lastname AND u IN :filtered")
    List<User> findAllByLastnameAndUserIn(
            @Param("lastname") String lastname,
            @Param("filtered") List<User> filtered
    );

    @Query("SELECT DISTINCT u FROM User u WHERE u.username = :username AND u IN :filtered")
    List<User> findAllByUsernameAndUserIn(
            @Param("username") String username,
            @Param("filtered") List<User> filtered
    );
}
