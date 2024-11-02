package com.project.StudentManagement.controller;

import com.project.StudentManagement.entity.ErrorResponse;
import com.project.StudentManagement.entity.Users;
import com.project.StudentManagement.entity.MarkSheet;
import com.project.StudentManagement.entity.UsersPrincipal;
import com.project.StudentManagement.service.JWTService;
import com.project.StudentManagement.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserDetailsService userDetailService;
    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTService jwtService;

    // Admin can add users with role Teacher or Student
    @PostMapping
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> addUser(@RequestBody Users user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT") || currentRole.equals("TEACHER")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(new ErrorResponse("Access Denied"));
        }
        Users savedUser = userService.createUser(user);
        return ResponseEntity.ok(savedUser);
    }

    // Teacher can add users with role Student
    @PostMapping("/student")
   // @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<?> addStudent(@RequestBody Users user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT") || user.getRole().equals("TEACHER")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(new ErrorResponse("Access Denied"));
        }
        Users savedUser = userService.createUser(user);
        return ResponseEntity.ok(savedUser);
    }

    // Teacher can update Student details
    @PutMapping("/student/{id}")
 //   @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<?> updateStudent(@PathVariable Long id, @RequestBody Users userDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT") ) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(new ErrorResponse("Access Denied"));
        }
        return ResponseEntity.ok(userService.updateUser(id, userDetails));
    }

    // Admin and Teacher can see details of any user with role Student
    @GetMapping("/{id}")
    //@PreAuthorize("hasAnyRole('ADMIN', 'TEACHER')")
    public Object getUserById(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT") ) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(new ErrorResponse("Access Denied"));
        }
        return userService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Student can update their own details (not marksheet)
    @PutMapping("/self/{id}")
    @PreAuthorize("hasRole('STUDENT') and #id == authentication.principal.id")
    public ResponseEntity<?> updateSelf(@PathVariable Long id, @RequestBody Users userDetails) {
        // Retrieve the user and ensure only the user can update their details
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
//        String currentRole = userPrincipal.getRole();
//        if (currentRole.equals("STUDENT") || userPrincipal.getId()==id) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
//                    .body(new ErrorResponse("You cannot update this user"));
//        }
        Users user = userService.getUserById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

//        user.setName(userDetails.getName());
//        user.setPassword(userDetails.getPassword());
//       // user.setStatus(userDetails.getStatus());
//        user.setMobile_number(userDetails.getMobile_number());

        return ResponseEntity.ok(userService.updateUser2(id, userDetails));
    }

    // Update marksheet - Accessible by ADMIN and TEACHER
    @PutMapping("/{userId}/marksheet")
 //   @PreAuthorize("hasAnyRole('ADMIN', 'TEACHER')")
    public ResponseEntity<?> updateMarkSheet(@PathVariable Long userId, @RequestBody MarkSheet marksheet) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(new ErrorResponse("You cannot update this user"));
        }
        MarkSheet updatedMarkSheet = userService.updateMarkSheet(userId, marksheet);
        return ResponseEntity.ok(updatedMarkSheet);
    }

    // Get all users - Admin only
    //@PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<?> getAllUsers() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        String currentRole = userPrincipal.getRole();
        if (currentRole.equals("STUDENT")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN) // 403 Forbidden
                    .body(Collections.singletonList(new ErrorResponse("Access Denied")));
        }

        List<Users> users= userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PostMapping("/uploadImage")
    public ResponseEntity<?> uploadImage(@RequestParam() MultipartFile file){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
        return ResponseEntity.ok(userService.uploadImage(file,userPrincipal));
    }



    @PostMapping("/createToken")
    public ResponseEntity<String> createToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            final String[] values = credentials.split(":", 2);

            String username = values[0];
            String password = values[1];

            // Authenticate user
            try {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
                // If successful, generate and return the token
                String token = jwtService.generateToken(username);
                return ResponseEntity.ok(token);
            } catch (BadCredentialsException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Authorization header missing or invalid");
    }

//    @PostMapping("/createToken")
//    public ResponseEntity<String> createToken(){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        UsersPrincipal userPrincipal = (UsersPrincipal) authentication.getPrincipal();
//        return ResponseEntity.ok(userService.verify(userPrincipal));
//    }
}

