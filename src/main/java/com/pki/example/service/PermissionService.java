package com.pki.example.service;

import com.pki.example.model.Permission;
import com.pki.example.repo.PermissionRepository;
import com.pki.example.repo.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PermissionService {

    @Autowired
    private PermissionRepository permissionRepository;

    public Permission createPermission(Permission permission)
    {
        return permissionRepository.save(permission);
    }
    public Permission findPermissionByName(String name)
    {
        return permissionRepository.findOneByName(name);
    }
    public List<Permission> getAllPermissions()
    {
        return permissionRepository.findAll();
    }
}
