package com.pki.example.repo;

import com.pki.example.model.Role;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role,Integer> {
    Role findOneById(int id);
    Role findOneByName(String name);
}
