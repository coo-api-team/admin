package com.coocon.admin.member;

import com.coocon.admin.oauth.entity.Provider;
import com.coocon.admin.oauth.entity.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import lombok.*;

import javax.persistence.*;

@Entity
@Table(name ="MEMBER")
@Getter
@Setter
@NoArgsConstructor
@ToString
public class Member {

    @JsonIgnore
    @Id
    @Column(name = "USER_SEQ")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long seq;
    @Column(unique = true)
    @NotNull
    private String id;

    private String name;


    @Column(unique = true, nullable = false)
    private String oAuth2Id;

    @Column(unique = true)
    private String email;

    private String password;

    @Column
    @Enumerated(value = EnumType.STRING)
    private Role role;

    @Column
    @Enumerated(value = EnumType.STRING)
    private Provider provider;


    @Builder
    Member(String id, String password,String email,  String name, Role role
            ,Provider provider ){
        this.id = id;
        this.password = password;
        this.name = name;
        this.role = role;
        this.email = email;
        this.provider = provider;
    }
}
