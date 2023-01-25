package com.coocon.admin.member;

import com.coocon.admin.oauth.entity.Provider;
import com.coocon.admin.oauth.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import net.bytebuddy.build.Plugin;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.nio.file.attribute.UserPrincipal;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Setter
@AllArgsConstructor
@RequiredArgsConstructor
public class MemberPrincipal implements OAuth2User, UserDetails, OidcUser {

    private final String id;
    private final String password;
    private final Provider provider;
    private final Role role;
    private final Collection<GrantedAuthority> authorities;
    private Map<String,Object> attributes;

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return id;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getClaims() {
        return null;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return id;
    }

    public static MemberPrincipal create(Member member){
        return new MemberPrincipal(
                member.getMemberId(),
                member.getPassword(),
                member.getProvider(),
                Role.USER,
                Collections.singletonList(new SimpleGrantedAuthority(Role.USER.getCode()))
        );
    }

    public static MemberPrincipal create(Member member, Map<String,Object> attributes){
        MemberPrincipal memberPrincipal = create(member);
        memberPrincipal.setAttributes(attributes);

        return memberPrincipal;
    }
}
