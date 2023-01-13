package com.coocon.admin.oauth.info;

import java.util.Map;

public class CooconOAuth2UserInfo extends OAuth2UserInfo{

    public CooconOAuth2UserInfo(Map<String,Object> attributes){
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
