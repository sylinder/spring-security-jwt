package com.caps.springsecurityjwt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private List<String> ignoreUrls = new ArrayList<>();
}
