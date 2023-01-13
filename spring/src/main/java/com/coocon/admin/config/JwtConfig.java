package com.coocon.admin.config;

import com.coocon.admin.oauth.token.AuthTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {
    //TODO get from properties
    private String secret = "12345678901234567890123456789012";

    @Bean
    public AuthTokenProvider jwtProvider(){
        return new AuthTokenProvider(secret);
    }
}
