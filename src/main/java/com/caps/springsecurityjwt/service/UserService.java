package com.caps.springsecurityjwt.service;

import com.caps.springsecurityjwt.common.CommonResult;
import com.caps.springsecurityjwt.domain.dto.LoginForm;
import com.caps.springsecurityjwt.domain.dto.RegisterForm;
import com.caps.springsecurityjwt.domain.dto.TokenInfo;
import com.caps.springsecurityjwt.domain.dto.UserDTO;
import com.caps.springsecurityjwt.domain.entity.UserPo;
import com.caps.springsecurityjwt.domain.vo.User;
import com.caps.springsecurityjwt.exception.CommonException;
import com.caps.springsecurityjwt.repository.UserRepository;
//import com.caps.springsecurityjwt.repository.UserRoleRepository;
import com.caps.springsecurityjwt.utils.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    private JwtUtil jwtUtil;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public CommonResult<List<UserDTO>> findAllUsers() {
        List<UserDTO> userDTOS = userRepository.findAll().stream().map(User::fromPo).map(User::toDTO).collect(Collectors.toList());
        return CommonResult.success(userDTOS);
    }

    public CommonResult<String> register(RegisterForm registerForm) {
        UserPo existUserPo = userRepository.findByUsername(registerForm.getUsername());
        if (existUserPo != null) {
            throw new CommonException("username already exist");
        }
        UserPo userPo = UserPo.builder().username(registerForm.getUsername()).password(passwordEncoder.encode(registerForm.getPassword())).build();
        userRepository.save(userPo);
        return CommonResult.success("register successfully");
    }

    public CommonResult<TokenInfo> login(LoginForm loginForm) {
        UserPo userPo = userRepository.findByUsername(loginForm.getUsername());
        if (!passwordEncoder.matches(loginForm.getPassword(), userPo.getPassword())) {
            throw new CommonException("Password is incorrect.");
        }
        TokenInfo tokenInfo = TokenInfo.builder()
                .username(userPo.getUsername())
                .token(jwtUtil.generateToken(userPo.getUsername()))
                .refreshToken("refreshToken")
                .build();

        return CommonResult.success(tokenInfo);
    }

    public CommonResult<UserDTO> findByUsername(String username) {
        UserPo userPo = userRepository.findByUsername(username);
        return CommonResult.success(User.fromPo(userPo).toDTO());
    }
}
