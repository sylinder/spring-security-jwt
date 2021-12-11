package com.caps.springsecurityjwt.service;

import com.caps.springsecurityjwt.domain.entity.UserPo;
import com.caps.springsecurityjwt.domain.entity.UserRolePo;
import com.caps.springsecurityjwt.domain.vo.SecurityUser;
import com.caps.springsecurityjwt.repository.UserRepository;
import com.caps.springsecurityjwt.repository.UserRoleRepository;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private UserRepository userRepository;

    private UserRoleRepository userRoleRepository;

    public UserDetailsServiceImpl(UserRepository userRepository, UserRoleRepository userRoleRepository) {
        this.userRepository = userRepository;
        this.userRoleRepository = userRoleRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserPo userPo = userRepository.findByUsername(username);
        if (userPo == null) {
            throw new UsernameNotFoundException("Username Not Found.");
        }
        List<UserRolePo> userRolePos = userRoleRepository.findByUsername(username);
        List<String> roles = userRolePos.stream().map(UserRolePo::getName).collect(Collectors.toList());

        return SecurityUser.builder()
                .username(userPo.getUsername())
                .password(userPo.getPassword())
                .authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", roles)))
                .build();
    }
}
