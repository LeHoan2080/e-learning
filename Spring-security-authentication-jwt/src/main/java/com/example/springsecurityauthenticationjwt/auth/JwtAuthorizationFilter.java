package com.example.springsecurityauthenticationjwt.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final ObjectMapper mapper;

    public JwtAuthorizationFilter(JwtUtil jwtUtil, ObjectMapper mapper) {
        this.jwtUtil = jwtUtil;
        this.mapper = mapper;
    }

    @Override
    //xử lý quá trình xác thực cho các yêu cầu HTTP đến.
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Map<String, Object> errorDetails = new HashMap<>();
        try {
            //lấy ra access token từ yêu cầu HTTP
            String accessToken = jwtUtil.resolveToken(request);
            if (accessToken == null ) {
                //yêu cầu tiếp tục đi qua chuỗi bộ lọc
                filterChain.doFilter(request, response);
                return;
            }

            //lấy ra các claims
            Claims claims = jwtUtil.resolveClaims(request);
            if(claims != null & jwtUtil.validateClaims(claims)){
                //trích xuất email
                String email = claims.getSubject();
                System.out.println("email : "+email);
                //tạo ra một đối tượng UsernamePasswordAuthenticationToken với email làm principal
                Authentication authentication = new UsernamePasswordAuthenticationToken(email,"",new ArrayList<>());
                //thiết lập đối tượng xác thực này trong SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }catch (Exception e){
            //thiết lập chi tiết lỗi
            errorDetails.put("message", "Authentication Error");
            errorDetails.put("details",e.getMessage());
            //hiết lập trạng thái HTTP response thành FORBIDDEN
            // chi tiết lỗi vào response
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            mapper.writeValue(response.getWriter(), errorDetails);
        }
        //yêu cầu tiếp tục đi qua chuỗi bộ lọc
        filterChain.doFilter(request, response);
    }
}
