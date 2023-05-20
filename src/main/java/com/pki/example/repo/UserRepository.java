package com.pki.example.repo;

import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    User findOneByUsername(String username);
    User findByActivationCode(String activationCode);
    User findByUsernameAndPassword(String username, String password);
}
