package com.ani.securty.jwtdemo.auth;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public enum AppRole {

    ADMIN(
            Set.of(
                    AppPermission.ADMIN_DASHBOARD,
                    AppPermission.USER_DASHBOARD
            )
    ),
    USER(
            Set.of(
                    AppPermission.USER_DASHBOARD
            )
    );

    private final Set<AppPermission> permissions;

    AppRole(Set<AppPermission> permissions) {
        this.permissions = permissions;
    }
    public Set<AppPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> grantedAuthorities() {

//        final Set<SimpleGrantedAuthority> authorities = new HashSet<>();
//        for( AppPermission permission : getPermissions() ) {
//                authorities.add(new SimpleGrantedAuthority(permission.getPermission()));
//        }

        var authorities = getPermissions()
                .stream()
                .map(
                    permission -> new SimpleGrantedAuthority(permission.getPermission())
                ).collect(Collectors.toSet());
        authorities.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return authorities;
    }
}
