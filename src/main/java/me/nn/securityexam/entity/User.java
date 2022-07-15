package me.nn.securityexam.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "TB_SD_USER")
public class User {

    @Id
    @GeneratedValue
    private long id;



}
