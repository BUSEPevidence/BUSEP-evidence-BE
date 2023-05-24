package com.pki.example.repo;

import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    User findOneByUsername(String username);
    User findByActivationCode(String activationCode);
    User findByUsernameAndPassword(String username, String password);
    Boolean existsByUsername(String username);

}
