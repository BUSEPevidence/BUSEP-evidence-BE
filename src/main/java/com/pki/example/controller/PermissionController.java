package com.pki.example.controller;

import ch.qos.logback.classic.Logger;
import com.pki.example.dto.PermissionDTO;
import com.pki.example.dto.RoleDTO;
import com.pki.example.dto.RolePermissionDTO;
import com.pki.example.model.Permission;
import com.pki.example.model.Role;
import com.pki.example.service.PermissionService;
import com.pki.example.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/permission")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PermissionController {

    private final PermissionService permissionService;
    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);

    @PostMapping("/addPermission")
    @PreAuthorize("hasAuthority('CREATE_PERMISSION')")
    public ResponseEntity<String> addPermission(@RequestBody PermissionDTO permissionDTO)
    {
        Permission permission = new Permission(permissionDTO.getName());
        permissionService.createPermission(permission);
        logger.info("Permission created: " + permission.getName());
        simpMessagingTemplate.convertAndSend("/logger/logg", "Permission created: " + permission.getName());
        return ResponseEntity.ok("{\"Message\": \"" + "Permission created" + "\"}");
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
