package com.project.StudentManagement.service;

import com.amazonaws.HttpMethod;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.project.StudentManagement.entity.Users;
import com.project.StudentManagement.entity.UsersPrincipal;
import com.project.StudentManagement.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.project.StudentManagement.entity.MarkSheet;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    @Autowired
    private UserRepo userRepo;

    @Autowired
    private AmazonS3 client;

    @Value("${app.s3.bucket}")
    private String bucketName;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    private JWTService jwtService;

    private BCryptPasswordEncoder encoder=new BCryptPasswordEncoder(12);
    public Users createUser(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        Users user2=userRepo.save(user);
//        user.setToken(this.createToken(user));
        return user2;
    }

    public Optional<Users> getUserById(Long id) {
        Optional<Users> user= userRepo.findById(id);
        return user;
    }

    public Users updateUser(Long id, Users userDetails) {
        Users user = userRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setName(userDetails.getName());
        user.setPassword(encoder.encode(userDetails.getPassword()));
        user.setRole(userDetails.getRole());
        user.setStatus(userDetails.getStatus());
        user.setMobile_number(userDetails.getMobile_number());
//        user.setToken(this.createToken(user));
        return userRepo.save(user);
    }

    public void deleteUser(Long id) {
        Users user = userRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepo.delete(user);
    }

    public List<Users> getAllUsers() {
        return userRepo.findAll();
    }

    // Method to update marksheet
    public MarkSheet updateMarkSheet(Long userId, MarkSheet marksheet) {
        Users user = userRepo.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setMarksheet(marksheet);
        userRepo.save(user); // Save user to persist the marksheet update
        return marksheet;
    }

    public Users updateUser2(Long id, Users userDetails) {
        Users user = userRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setName(userDetails.getName());
        user.setPassword(encoder.encode(userDetails.getPassword()));
        user.setMobile_number(userDetails.getMobile_number());
        return userRepo.save(user);
    }

    public String uploadImage(MultipartFile image, UsersPrincipal user){
        String actualFileName=image.getOriginalFilename();
        String fileName= UUID.randomUUID().toString()+actualFileName.substring(actualFileName.lastIndexOf("."));
        ObjectMetadata metaData=new ObjectMetadata();
        metaData.setContentLength(image.getSize());
        try{
            PutObjectResult putObjectResult=client.putObject(new PutObjectRequest(bucketName,fileName,image.getInputStream(),metaData));
//            Users user2=userRepo.findById(user.getId());
//            user2.setDpURL(this.preSignedUrl(fileName));
            Users user2 = userRepo.findById(user.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user2.setDpURL(this.preSignedUrl(fileName));
            userRepo.save(user2);
            return "Image Uploaded";
        } catch (IOException e) {
            return "Image Not Uploaded";
        }
    }
    public String preSignedUrl(String fileName) {
        Date expirationDate=new Date();
        long time= expirationDate.getTime();
        int hour=2;
        time +=hour*60*60*1000;
        expirationDate.setTime(time);
        GeneratePresignedUrlRequest generatePresignedUrlRequest= new GeneratePresignedUrlRequest(bucketName,fileName)
                .withMethod(HttpMethod.GET)
                .withExpiration(expirationDate);
        URL url=client.generatePresignedUrl(generatePresignedUrlRequest);
        return url.toString();
    }

//    public String verify(UsersPrincipal userPrincipal) {
//        String username = userPrincipal.getUsername();
//            String password =userPrincipal.getPassword();
//
//            // Authenticate user
//            try {
//                authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
//                // If successful, generate and return the token
//                String token = jwtService.generateToken(username);
//                return token;
//            } catch (BadCredentialsException e) {
//                return "Invalid credentials";
//            }
////        Authentication authentication=authManager.authenticate(new UsernamePasswordAuthenticationToken(userPrincipal.getUsername(),userPrincipal.getPassword()));
////        if(authentication.isAuthenticated())
////            return jwtService.generateToken(userPrincipal.getUsername());
////        return "fail";
//    }

}
