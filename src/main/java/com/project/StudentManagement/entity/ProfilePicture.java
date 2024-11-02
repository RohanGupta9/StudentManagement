package com.project.StudentManagement.entity;

import jakarta.persistence.*;

@Entity
public class ProfilePicture {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String imageUrl;

}
