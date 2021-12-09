package com.caps.springsecurityjwt.domain.vo;

import com.caps.springsecurityjwt.domain.dto.UserDTO;
import com.caps.springsecurityjwt.domain.entity.UserPo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Long id;

    private String username;

    private String password;

    public UserDTO toDTO() {
        return UserDTO.builder()
                .username(this.username)
                .password(this.password)
                .build();
    }

    public static User fromPo(UserPo userPo) {
        if (userPo == null) {
            return null;
        }
        return User.builder()
                .id(userPo.getId())
                .username(userPo.getUsername())
                .password(userPo.getPassword())
                .build();
    }
}
