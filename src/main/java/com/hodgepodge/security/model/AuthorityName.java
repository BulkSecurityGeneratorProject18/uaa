package com.hodgepodge.security.model;

import java.io.Serializable;
import java.util.StringJoiner;

public enum AuthorityName implements Serializable {

    ROLE_ADMIN("ROLE_ADMIN"), ROLE_USER("ROLE_USER"), ROLE_NONE("ROLE_NONE");

    private static final long serialVersionUID = 4L;
    private final String role;

    AuthorityName(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", AuthorityName.class.getSimpleName() + "[", "]")
                .add("role='" + role + "'")
                .toString();
    }
}
