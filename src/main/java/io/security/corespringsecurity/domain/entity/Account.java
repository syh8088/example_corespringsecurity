package io.security.corespringsecurity.domain.entity;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "z_test_security_account")
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column
    private String username;

    @Column
    private String email;

    @Column
    private int age;

    @Column
    private String password;

    @Column
    private String role;

}
