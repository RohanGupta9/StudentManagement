package com.project.StudentManagement.service;

import com.project.StudentManagement.entity.Users;
import com.project.StudentManagement.repo.UserRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {
    @Autowired
    private UserRepo repo;
    private String secretkey="";
    public JWTService(){
        try {
            KeyGenerator keyGen=KeyGenerator.getInstance("HmacSHA256");//This line retrieves a KeyGenerator instance for the "HmacSHA256" algorithm.
            SecretKey sk=keyGen.generateKey();//The generateKey() method generates a new secret key for the specified algorithm
            secretkey= Base64.getEncoder().encodeToString(sk.getEncoded());//The sk.getEncoded() method retrieves the raw byte array of the generated secret key
            //Base64.getEncoder().encodeToString(...) converts this byte array into a Base64-encoded String
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
//
public String generateToken(String username) {
    Map<String, Object> claims = new HashMap<>();
    Users userDetails = repo.findByName(username);
    Users user = repo.findByName(username);

    claims.put("role:",user.getRole());
    claims.put("status:",user.getStatus());
    return createToken(claims, username);
}
    public String createToken(Map<String, Object> claims,String username) {
        //Map<String,Object> claims = new HashMap<>();//This creates a HashMap to hold claims that can be included in the payload of the JWT. Claims are pieces of information about the user or the context, such as roles, permissions, or other metadata.
        return Jwts.builder()//This initiates the creation of a JWT using the Jwts.builder() method from the jjwt library.
                .subject(username)//Sets the subject of the token, which is usually the username or user ID. This is typically used to identify the user for whom the token was issued.
                .issuedAt(new Date(System.currentTimeMillis()))//Sets the timestamp for when the token was issued. System.currentTimeMillis() gets the current time in milliseconds, which is wrapped in a Date object.
                .expiration(new Date(System.currentTimeMillis()+60*60*30))//Sets the expiration time of the token.
                .claims()
                .add(claims)
                .and()
                .signWith(getKey())//This method signs the JWT with a secret key. The getKey() method should return a Key object that represents the key used to sign the token. This is crucial for the token's integrity and authenticity.
                .compact();//Finally, this method compacts the JWT into a String representation, which can be returned and sent to the client.
    }
    private SecretKey getKey() {
        byte[] keyBytes= Decoders.BASE64.decode(secretkey);//This converts the String key into Bytes
        return Keys.hmacShaKeyFor(keyBytes);//This method call creates a Key object specifically designed for HMAC operations using the SHA algorithm.
    }
    public String extractUserName(String token) {
        // extract the username from jwt token
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
