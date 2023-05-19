package com.pki.example.service;

import com.pki.example.model.DenialRequests;
import com.pki.example.model.Role;
import com.pki.example.repo.DenialRequestsRepository;
import com.pki.example.repo.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
@Service
public class RoleService {
    @Autowired
    public RoleRepository roleRepository;


    public Role findRole(int id)
    {
        return roleRepository.findOneById(id);
    }

    public Role addPermission(Role role)
    {
        return roleRepository.save(role);
    }

    public Role findRoleByName(String name) { return roleRepository.findOneByName(name);}
    public Role save(Role role) { return roleRepository.save(role);}
    public List<Role> getAll() { return roleRepository.findAll();}

}
