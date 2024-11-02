package com.project.StudentManagement.config;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class S3Config {
    @Value("${cloud.aws.credentials.access-key}")
    private String awsAccessKey;
    @Value("${cloud.aws.credentials.secret-key}")
    private String awsSecretKey;
    @Value("${cloud.aws.region.static}")
    private String region;
    @Bean
    public AmazonS3 client(){
        AWSCredentials credentials=new BasicAWSCredentials(awsAccessKey,awsSecretKey);//This line creates an instance of AWSCredentials using your AWS access key and secret key. These credentials are necessary to authenticate your application with AWS services.
        AmazonS3 amazonS3= AmazonS3ClientBuilder//This is a builder class provided by the AWS SDK to create an instance of the AmazonS3 client, which is used to interact with Amazon S3
                .standard()//This method initializes a default AmazonS3ClientBuilder. It sets up the builder with standard configurations.
                .withCredentials(new AWSStaticCredentialsProvider(credentials))//This method specifies the credentials to use when authenticating with AWS services.
                //AWSStaticCredentialsProvider is used to provide static AWS credentials (access key and secret key). The credentials object should be an instance of AWSCredentials that contains your AWS access key and secret key.
                .withRegion(region)//his method sets the AWS region in which the S3 service is accessed
                .build();//This method finalizes the configuration and creates an instance of AmazonS3 with the specified settings
        return amazonS3;
    }
}
