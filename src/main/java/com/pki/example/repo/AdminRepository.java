package com.pki.example.repo;

import com.pki.example.model.AdminLogins;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdminRepository  extends JpaRepository<AdminLogins,Integer> {
    public AdminLogins getAdminLoginsByUser(User user);
    public AdminLogins findOneByUserId(int userId);
}
