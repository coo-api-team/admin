package com.coocon.admin.member;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRefreshTokenRepository extends JpaRepository<MemberRefreshToken,Long> {
    MemberRefreshToken findByMemberId(String memberId);
    MemberRefreshToken findByMemberIdAndRefreshToken(String memberId, String refreshToken);
}
