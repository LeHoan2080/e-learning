package com.example.springsecurityauthenticationjwt.auth;

import com.example.springsecurityauthenticationjwt.services.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // class cấu hình, nó cho phép Spring tạo ra các bean (đối tượng) và cấu hình ứng dụng
@EnableWebSecurity //bật tính năng bảo mật web.
public class SecurityConfig  {
    private final CustomUserDetailsService userDetailsService;

    //JwtAuthorizationFilter là một bộ lọc (filter) được sử dụng để xác thực và ủy quyền người dùng dựa trên JWT (JSON Web Token)
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    // contructor(phương thức khởi tạo) của lớp SecurityConfig
    public SecurityConfig(CustomUserDetailsService customUserDetailsService, JwtAuthorizationFilter jwtAuthorizationFilter) {
        this.userDetailsService = customUserDetailsService;
        this.jwtAuthorizationFilter = jwtAuthorizationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, NoOpPasswordEncoder noOpPasswordEncoder)
            throws Exception {
        // tạo ra một AuthenticationManager, chịu trách nhiệm xác thực người dùng
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        // , authenticationManagerBuilder sử dụng userDetailsService làm nguồn dữ liệu người dùng và sử dụng noOpPasswordEncoder để mã hóa mật khẩu
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(noOpPasswordEncoder);

        // tạo ra AuthenticationManager bean.
        return authenticationManagerBuilder.build();
    }


    // tạo bean securityFilterChain chịu trách nhiệm xác định các quy tắc bảo mật và lọc các yêu cầu HTTP
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //vô hiệu hóa bảo mật CSRF
        http.csrf(csrf -> csrf.disable())
                //cấu hình các quy tắc xác thực
                .authorizeHttpRequests(request -> {
                    //Cho phép truy cập vào các đường dẫn bắt đầu bằng /rest/auth/** mà không cần xác thực.
                    request.requestMatchers("/rest/auth/**").permitAll();
                    //Yêu cầu xác thực đối với tất cả các yêu cầu khác.
                    request.anyRequest().authenticated();
                })
                //ấu hình chính sách quản lý phiên, chế độ không trạng thái
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //hêm một bộ lọc jwtAuthorizationFilter trước bộ lọc UsernamePasswordAuthenticationFilter.
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    //mật khẩu được mã hóa, và được lưu trữ dưới dạng văn bản
    public NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }


}
