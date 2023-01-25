package com.coocon.admin.member;


import com.coocon.admin.oauth.entity.Provider;
import com.coocon.admin.oauth.entity.Role;
import org.aspectj.lang.annotation.Before;
import org.assertj.core.api.Assertions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestEntityManager;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.transaction.Transactional;


@DataJpaTest
@AutoConfigureTestDatabase(replace= AutoConfigureTestDatabase.Replace.NONE)
public class MemberRepositoryTest {

    @Autowired
    private MemberRepository memberRepository;

    @BeforeEach
    public void beforeEach(){

    }


    @Test
    @Transactional
    @Rollback(false)
    void saveMember(){
        //Given
        Member member = Member.builder()
                .memberId("Test1")
                .password("123")
                .name("쿠콘테스트")
                .email("test@coocon.net")
                .role(Role.ADMIN)
                .provider(Provider.COOCON)
                .build();

        //When
        member.setOAuth2Id("123");
        memberRepository.save(member);
        //Then
        Member resultMember=memberRepository.findByMemberId("Test1");
        System.out.println("###################"+member.getMemberId());
        System.out.println(member.getName());
        Assertions.assertThat(resultMember).isEqualTo(member);
    }

}
