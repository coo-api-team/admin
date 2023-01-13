package com.coocon.admin.oauth.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum Role {

    USER("ROLE_USER","일반 사용자 권한"),
    ADMIN("ROLE_ADMIN","관리자 권한"),
    GUEST("GUEST","게스트 권한");

    private final String code;
    private final String displayName;

    public static Role of(String code){
        return Arrays.stream(Role.values())
                .filter(r-> r.getCode().equals(code))
                .findAny()
                .orElse(GUEST);
    }

}