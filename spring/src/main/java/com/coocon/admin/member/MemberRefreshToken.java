package com.coocon.admin.member;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "MEMBER_REFRESH_TOKEN")
public class MemberRefreshToken {
    @JsonIgnore
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long seq;


    @Column(name = "USER_ID", length = 64, unique = true)
    @NotNull
    private String userId;

    @Column(name = "REFRESH_TOKEN", length = 256)
    @NotNull
    private String refreshToken;
}
