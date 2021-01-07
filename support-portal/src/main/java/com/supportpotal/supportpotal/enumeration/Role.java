package com.supportpotal.supportpotal.enumeration;

import com.supportpotal.supportpotal.constant.Authority;
import lombok.Getter;
import lombok.Setter;

@Getter
public enum Role {
    ROLE_USER(Authority.USER_AUTHORITIES),
    ROLE_HR(Authority.HR_AUTHORITIES),
    ROLE_MANAGER(Authority.MANAGER_AUTHORITIES),
    ROLE_ADMIN(Authority.ADMIN_AUTHORITIES),
    ROLE_SUPER_ADMIN(Authority.SUPER_ADMIN_AUTHORITIES);

    private String[] authorities;

    Role(String... authorities) {
        this.authorities = authorities;
    };

    public String[] authorities() {
        return authorities;
    }

}
