package com.ani.securty.jwtdemo.auth;

public enum AppPermission {
    ADMIN_DASHBOARD("dashboard:yes"),
    USER_DASHBOARD("user:yes");

    private final String permission;

    AppPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
