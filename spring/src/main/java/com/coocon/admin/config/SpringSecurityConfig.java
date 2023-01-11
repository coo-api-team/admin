package com.coocon.admin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SpringSecurityConfig {
    private static final String[] AUTH_WHITELIST ={
            "/static/*"
    };

    @Bean
    public BCryptPasswordEncoder encodePassword(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                //.exceptionHandling()
                //.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                //.accessDeniedHandler(jwtAccessDeniedHandler)
                .headers()
                .frameOptions()
                .sameOrigin();
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //.and()
                //.oauth2Login()
                //.authorizationEndpoint()
                //.authorizationRequestResolver()

                .and()
                .authorizeRequests()
                .antMatchers("/","/signUp","/access-denied","/exception/**","/auth/*").permitAll()
                .antMatchers( "/error",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js").permitAll() //정적리소스에 대한 접속 허용
                .antMatchers("/dashboard").hasRole("USER")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated(); //permit한 리소스 제외 접근 시 인증 필요

        http.oauth2Login()
                .userInfoEndpoint().userService(customOAuth2UserService)
                .and()
                .successHandler(configSuccessHandler())
                .failureHandler(configFailureHandler())
                .permitAll();

        //.and()

        //.and()
        //.formLogin().loginPage("/auth/signIn") //설정해두면 로그인 없는 상태로 들어가면 이 페이지로 redirect 시킨다.
        //.defaultSuccessUrl("/"); //로그인 성공 후 기본


        //.and()
        //.apply(new JwtSecurityConfig(tokenProvider));
        return http.build();
    }

    private CustomAuthenticationSuccessHandler configSuccessHandler() {
        /* ... */
    }

    private CustomAuthenticationFailureHandler configFailureHandler() {
        /* ... */
    }
}
