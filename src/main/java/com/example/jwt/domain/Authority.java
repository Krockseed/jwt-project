package com.example.jwt.domain;

public enum Authority {
    ROLE_USER("user"),
    ROLE_ADMIN("admin");

    private String desc;

    Authority(String desc) {
        this.desc = desc;
    }
}
