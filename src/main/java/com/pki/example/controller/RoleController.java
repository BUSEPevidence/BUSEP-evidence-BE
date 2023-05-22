package com.pki.example.controller;

import com.pki.example.auth.JwtService;
import com.pki.example.dto.RoleDTO;
import com.pki.example.dto.RolePermissionDTO;
import com.pki.example.model.Permission;
import com.pki.example.model.Role;
import com.pki.example.service.PermissionService;
import com.pki.example.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/role")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class RoleController {

    private final RoleService roleService;
    private final PermissionService permissionService;


    @PostMapping("/addPermission")
    public ResponseEntity<String> addPermissionToRole(@RequestBody RolePermissionDTO rolePermissionDTO)
    {
        System.out.println(rolePermissionDTO.getRole() + " " + rolePermissionDTO.getPermission());
        Role role = roleService.findRoleByName(rolePermissionDTO.getRole());
        Permission permission = permissionService.findPermissionByName(rolePermissionDTO.getPermission());
        System.out.println("rola je: " + role.getName() + " " + role.getId());
        System.out.println("permisija je: " + permission.getName() + " " + permission.getId());
        List<Permission> roles = role.getPermissions();
        roles.add(permission);
        role.setPermissions(roles);
        for(Permission perm : role.getPermissions())
        {
            System.out.println(perm.getName() + " eo perma");
        }
        roleService.save(role);

        return ResponseEntity.ok("{\"Answer\": \"" + "Added" + "\"}");
    }
    @PostMapping("/deletePermission")
    public ResponseEntity<String> deletePermission(@RequestBody RolePermissionDTO rolePermissionDTO)
    {
        Role role = roleService.findRoleByName(rolePermissionDTO.getRole());
        Permission permission = permissionService.findPermissionByName(rolePermissionDTO.getPermission());
        List<Permission> roles = role.getPermissions();
        List<Permission> perms = new ArrayList<>();
        for(Permission perm : roles)
        {
            if(!permission.getName().equals(perm.getName()))
            {
                perms.add(perm);
            }
        }

        role.setPermissions(perms);
        roleService.save(role);

        return ResponseEntity.ok("{\"Answer\": \"" + "Deleted" + "\"}");
    }
    @GetMapping("/getForDelete")
    public List<RolePermissionDTO> getForDelete()
    {
        List<RolePermissionDTO> rolePermissionDTOS = new ArrayList<>();
        List<Role> roles = roleService.getAll();
        for(Role role: roles)
        {
            for(Permission permission : role.getPermissions())
            {
                rolePermissionDTOS.add(new RolePermissionDTO(role.getName(),permission.getName()));
            }
        }

        return rolePermissionDTOS;
    }
    @GetMapping("/getAll")
    public List<RoleDTO> getAllRoles()
    {
        List<RoleDTO> rolePermissionDTOS = new ArrayList<>();
        List<Role> roles = roleService.getAll();
        for(Role role: roles)
        {
                rolePermissionDTOS.add(new RoleDTO(role.getName()));
        }

        return rolePermissionDTOS;
    }
}
