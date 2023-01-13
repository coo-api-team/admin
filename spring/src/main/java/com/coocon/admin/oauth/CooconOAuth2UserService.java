package com.coocon.admin.oauth;

import com.coocon.admin.member.Member;
import com.coocon.admin.member.MemberPrincipal;
import com.coocon.admin.member.MemberRepository;
import com.coocon.admin.oauth.entity.Provider;
import com.coocon.admin.oauth.entity.Role;
import com.coocon.admin.oauth.info.OAuth2UserInfo;
import com.coocon.admin.oauth.info.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class CooconOAuth2UserService  implements OAuth2UserService<OAuth2UserRequest,OAuth2User> {
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest,OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oauth2User = delegate.loadUser(userRequest);

        try{
            return this.process(userRequest,oauth2User);
        } catch(AuthenticationException e){
            throw e;
        } catch (Exception e){
            e.printStackTrace();
            throw new InternalAuthenticationServiceException(e.getMessage(),e.getCause());
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User user){
        Provider provider = Provider.valueOf(userRequest.getClientRegistration()
                .getRegistrationId().toUpperCase());

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(provider,user.getAttributes());
        Member savedMember = memberRepository.findById(userInfo.getId()).get();

        if(savedMember != null){
            if(provider != savedMember.getProvider()){
                throw new OAuthProviderMissMatchException("Request provider type is ["+ provider
                        + "] use [" +savedMember.getProvider() + "]");
            }

            updateMember(savedMember,userInfo);
        }else{
            savedMember = createMember(userInfo,provider);
        }

        return MemberPrincipal.create(savedMember,user.getAttributes() );
    }

    private Member createMember(OAuth2UserInfo userInfo, Provider provider ){
        LocalDateTime now = LocalDateTime.now();
        Member member = Member.builder()
                .id(userInfo.getId())
                .name(userInfo.getName())
                .email(userInfo.getEmail())
                .provider(provider)
                .role(Role.USER)
                .build();

        return memberRepository.saveAndFlush(member);
    }

    private Member updateMember(Member member, OAuth2UserInfo userInfo){
        /*
        바뀔수 있는 정보에 대한 업데이트
         */

        return member;
    }
}
