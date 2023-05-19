package com.pki.example.controller;

import com.pki.example.dto.PermissionDTO;
import com.pki.example.dto.RoleDTO;
import com.pki.example.dto.RolePermissionDTO;
import com.pki.example.model.Permission;
import com.pki.example.model.Role;
import com.pki.example.service.PermissionService;
import com.pki.example.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/permission")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PermissionController {

    private final PermissionService permissionService;


    @PostMapping("/addPermission")
    public ResponseEntity<String> addPermission(@RequestBody PermissionDTO permissionDTO)
    {
        Permission permission = new Permission(permissionDTO.getName());
        permissionService.createPermission(permission);
        return ResponseEntity.ok("Hello man with valid token");
    }
    @GetMapping("/getAll")
    public List<PermissionDTO> getAllPermissions()
    {
        List<PermissionDTO> rolePermissionDTOS = new ArrayList<>();
        List<Permission> roles = permissionService.getAllPermissions();
        for(Permission role: roles)
        {
            rolePermissionDTOS.add(new PermissionDTO(role.getName()));
        }

        return rolePermissionDTOS;
    }
}
