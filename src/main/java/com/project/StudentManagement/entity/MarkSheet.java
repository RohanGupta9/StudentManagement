package com.project.StudentManagement.entity;

import jakarta.persistence.*;
import lombok.Data;

@Embeddable
@Entity
@Data
public class MarkSheet {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private int maths;
    private int physics;
    private int chemistry;

}
