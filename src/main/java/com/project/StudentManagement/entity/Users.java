package com.project.StudentManagement.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String password; // Password field

    private String role;

    private String status;

    private Long mobile_number;

    @OneToOne(cascade = CascadeType.ALL)
    private MarkSheet marksheet;

    private String dpURL;

    public void setDpURL(String dpURL) {
        this.dpURL = dpURL;
    }

}
