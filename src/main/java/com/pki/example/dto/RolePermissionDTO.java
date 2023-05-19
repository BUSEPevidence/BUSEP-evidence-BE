package com.pki.example.dto;

public class RolePermissionDTO {

    String role;
    String permission;

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public RolePermissionDTO(String role, String permission) {
        this.role = role;
        this.permission = permission;
    }
}
