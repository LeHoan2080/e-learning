package com.example.springsecurityauthenticationjwt.models.response;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRes {
    private String email;
    private String token;

}
