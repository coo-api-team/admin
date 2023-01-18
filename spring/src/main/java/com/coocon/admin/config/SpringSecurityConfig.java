package com.coocon.admin.config;

import com.coocon.admin.oauth.CooconOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SpringSecurityConfig {

    private final CooconOAuth2UserService cooconOAuth2UserService;
    
    private static final String[] AUTH_WHITELIST ={
            "/static/*"
    };

    @Bean
    public BCryptPasswordEncoder encodePassword(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http   .csrf().disable() //browser로부터 직접 받는게 아닐경우
                .headers().frameOptions().sameOrigin()
                .and().logout().logoutSuccessUrl("/");
        http.cors();

        http    .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS); //세션으로 진행하지 않음

        http    .authorizeRequests()
                .antMatchers("/","/signUp","/access-denied","/exception/**").permitAll()
                .antMatchers("/oauth2/*").permitAll()
                .antMatchers( "/error").permitAll() //정적리소스에 대한 접속 허용
                .antMatchers("/dashboard").hasRole("USER")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated(); //permit한 리소스 제외 접근 시 인증 필요

        http.oauth2Login()
                .loginPage("http://localhost:3000/pages/login/login3")
                .userInfoEndpoint().userService(cooconOAuth2UserService); //로그인 성공시 서비스

        return http.build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.addAllowedOriginPattern("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod(HttpMethod.POST);
        corsConfiguration.addAllowedMethod(HttpMethod.GET);
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",corsConfiguration);
        return source;
    }

    List<String> clients = Arrays.asList("google","coocon","facebook");
    /*
        provider에 대한 초기 설정 bean
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        List<ClientRegistration> registrations = clients.stream()
                .map(client -> getRegistration(client))
                .filter(registration -> registration != null)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";
    private ClientRegistration getRegistration(String client) {
        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

        if (clientId == null) {
            return null;
        }

        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
        if (client.equals("google")) {
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        if (client.equals("facebook")) {
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        if(client.equals("coocon")){
            return getCooconRegistration().clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        return null;
    }
    @Autowired
    private Environment env;

    public ClientRegistration.Builder getCooconRegistration(){
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId("coocon");

        builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}");//DEFAULT_REDIRECT_URL
        builder.authorizationUri("http://localhost:8180/oauth2/v2/auth");
        builder.tokenUri("http://localhost:8180/oauth2/v2/token");
        builder.jwkSetUri("http://localhost:8180/oauth2/v2/certs");
        builder.issuerUri("http://localhost:8180");
        builder.userInfoUri("http://localhost:8180/oauth2/v2/userinfo");
        builder.userNameAttributeName("id");
        builder.scope("openid", "profile", "dashboard");
        builder.userNameAttributeName(IdTokenClaimNames.SUB);
        builder.clientName("Coocon");
        return builder;
    }

}
