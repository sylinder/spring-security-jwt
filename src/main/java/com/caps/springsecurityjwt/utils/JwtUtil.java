package com.caps.springsecurityjwt.utils;

import com.caps.springsecurityjwt.config.JwtTokenProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    private JwtTokenProperties jwtTokenProperties;

    public JwtUtil(JwtTokenProperties jwtTokenProperties) {
        this.jwtTokenProperties = jwtTokenProperties;
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expireData = new Date(now.getTime() + 1000 * jwtTokenProperties.getExpire());

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expireData)
                .signWith(SignatureAlgorithm.HS512, jwtTokenProperties.getSecret())
                .compact();
    }

    public Claims getClaimByToken(String jwt) {
        try {
            return Jwts.parser()
                    .setSigningKey(jwtTokenProperties.getSecret())
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (Exception exception) {
            return null;
        }
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}
