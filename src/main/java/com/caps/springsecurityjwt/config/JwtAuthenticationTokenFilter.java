package com.caps.springsecurityjwt.config;

import com.caps.springsecurityjwt.domain.entity.UserRolePo;
import com.caps.springsecurityjwt.repository.UserRoleRepository;
import com.caps.springsecurityjwt.service.UserDetailsServiceImpl;
import com.caps.springsecurityjwt.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private UserDetailsServiceImpl userDetailsService;

    private JwtTokenProperties jwtTokenProperties;

    private JwtUtil jwtUtil;

    private UserRoleRepository userRoleRepository;

    public JwtAuthenticationTokenFilter(UserDetailsServiceImpl userDetailsService, JwtTokenProperties jwtTokenProperties, JwtUtil jwtUtil, UserRoleRepository userRoleRepository) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenProperties = jwtTokenProperties;
        this.jwtUtil = jwtUtil;
        this.userRoleRepository = userRoleRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Claims claims = jwtUtil.getClaimByToken(request.getHeader(jwtTokenProperties.getHeader()));
        if (claims != null && !jwtUtil.isTokenExpired(claims)) {
            String username = claims.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (userDetails != null) {
                List<UserRolePo> userRoles = userRoleRepository.findByUsername(username);
                List<String> roles = userRoles.stream().map(UserRolePo::getName).collect(Collectors.toList());
                List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", roles));
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
