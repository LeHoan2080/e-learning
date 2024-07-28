package com.example.springsecurityauthenticationjwt.repositories;

import com.example.springsecurityauthenticationjwt.models.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    public User findUserByEmail(String email) {
        User user = new User(email, "123456");
        user.setFirstName("FistName");
        user.setLastName("LastName");
        return user;
    }
}
