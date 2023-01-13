package com.coocon.admin.oauth.info;

import com.coocon.admin.member.Member;
import com.coocon.admin.member.MemberPrincipal;
import com.coocon.admin.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CooconUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByMemberId(username);
        if(member == null){
            throw new UsernameNotFoundException("Can not find id");
        }
        return MemberPrincipal.create(member);
    }
}
