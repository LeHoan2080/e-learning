package com.example.springsecurityauthenticationjwt.services;

import com.example.springsecurityauthenticationjwt.models.User;
import com.example.springsecurityauthenticationjwt.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository; // Gán UserRepository vào thuộc tính của class
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findUserByEmail(email);

        if(user == null) {
            throw new UsernameNotFoundException("Email does not exist");
        }

        // Tạo một danh sách các vai trò (roles) của người dùng
        List<String> roles = new ArrayList<>();
        roles.add("USER");

        // Sử dụng Builder Pattern của User class (từ Spring Security) để tạo một UserDetails object
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail()) // Sử dụng email của user làm username
                .password(user.getPassword()) // Sử dụng password của user
                .roles(roles.toArray(new String[0])) // Sử dụng danh sách roles đã tạo
                .build(); // Xây dựng và trả về UserDetails object
    }
}
