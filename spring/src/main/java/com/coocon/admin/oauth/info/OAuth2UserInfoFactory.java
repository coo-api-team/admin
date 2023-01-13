package com.coocon.admin.oauth.info;

import com.coocon.admin.oauth.entity.Provider;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(Provider provider, Map<String,Object> attributes){
        switch(provider){
            case GOOGLE:
                throw new IllegalArgumentException("Google OAuth provider is not support!");
            case COOCON:
                return new CooconOAuth2UserInfo(attributes);
            default: throw new IllegalArgumentException("Invalid Provider Type");
        }
    }
}
