package com.pki.example.repo;

import com.pki.example.model.Permission;
import com.pki.example.model.User;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Configuration
@Repository
public interface PermissionRepository extends JpaRepository<Permission,Integer> {
    Permission findOneById(int id);
}
