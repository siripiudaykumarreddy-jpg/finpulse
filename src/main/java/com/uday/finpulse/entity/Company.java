package com.uday.finpulse.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Company {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String companyName;
    private String email;
    private String password; // stored as a BCrypt hash, never plain text
}
