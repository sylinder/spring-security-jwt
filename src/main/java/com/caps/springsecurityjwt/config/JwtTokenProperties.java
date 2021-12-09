package com.caps.springsecurityjwt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtTokenProperties {
    private String header;

    private String secret;

    private Long expire;
}
