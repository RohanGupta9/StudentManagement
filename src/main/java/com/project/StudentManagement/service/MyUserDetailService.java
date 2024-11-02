package com.project.StudentManagement.service;

import com.project.StudentManagement.entity.Users;
import com.project.StudentManagement.entity.UsersPrincipal;
import com.project.StudentManagement.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailService implements UserDetailsService {
    @Autowired
    private UserRepo repo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user=repo.findByName(username);
        if(user==null){
            throw new UsernameNotFoundException("User not found");
        }
        return new UsersPrincipal(user);
    }
}
