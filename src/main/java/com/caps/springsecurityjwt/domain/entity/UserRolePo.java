package com.caps.springsecurityjwt.domain.entity;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;


@Entity
@Table(name = "t_role")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRolePo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    private String roleName;
}
