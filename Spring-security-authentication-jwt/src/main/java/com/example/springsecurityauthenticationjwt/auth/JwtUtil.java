package com.example.springsecurityauthenticationjwt.auth;

import com.example.springsecurityauthenticationjwt.models.User;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;
import java.util.List;
//import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {

    private final String secret_key = "mysecretkey";
    private long accessTokenValidity = 60*60*1000; // 1h
    private final JwtParser jwtParser;
    private final String TOKEN_HEADER = "Authorization";
    private final String TOKEN_PREFIX = "Bearer ";
    public JwtUtil(){
        this.jwtParser = Jwts.parser().setSigningKey(secret_key);
    }
    public String createToken(User user) {
        // tạo một claims mới với chủ đề là email của người dùng
        Claims claims = Jwts.claims().setSubject(user.getEmail());

        // thêm claim vào claims
        claims.put("firstName",user.getFirstName());
        claims.put("lastName",user.getLastName());

        // Lấy thời điểm hiện tại làm thời điểm tạo token.
        Date tokenCreateTime = new Date();
        Duration duration = Duration.ofMinutes(accessTokenValidity);
        long milliseconds = duration.toMillis();

        //Tính toán thời điểm hết hạn của token
        Date tokenValidity = new Date(tokenCreateTime.getTime() + milliseconds);

        return Jwts.builder()
                //Thiết lập claims cho token
                .setClaims(claims)
                //Thiết lập thời điểm hết hạn của token
                .setExpiration(tokenValidity)
                //Ký token bằng thuật toán HS256 và một secret key.
                .signWith(SignatureAlgorithm.HS256, secret_key)
                //Tạo ra chuỗi JWT hoàn chỉnh.
                .compact();
    }

    //giải mã một token JWT (JSON Web Token) và lấy ra các claims (tuyên bố) từ token đó
    private Claims parseJwtClaims(String token) {
        return jwtParser.parseClaimsJws(token).getBody();
        //Phương thức parseClaimsJws được gọi trên jwtParser để giải mã token JWT và trả về một Jws<Claims> object
    }

    //định nghĩa một phương thức để lấy một token JWT từ request, giải mã token và trích xuất các claims từ đó.
    public Claims resolveClaims(HttpServletRequest req) {
        try {
            //lấy ra token JWT từ request.
            String token = resolveToken(req);
            if (token != null) {
                //gọi parseJwtClaims để giải mã token và trích xuất các claims từ token đó
                return parseJwtClaims(token);
            }
            return null;
        } catch (ExpiredJwtException ex) {
            //Nếu token JWT đã hết hạn, phương thức sẽ đặt một thuộc tính expired vào request, và ném ra một ExpiredJwtException
            req.setAttribute("expired", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            // phương thức sẽ đặt một thuộc tính invalid vào request, và ném ra ngoại lệ đó
            req.setAttribute("invalid", ex.getMessage());
            throw ex;
        }
    }

    //trích xuất một token JWT từ header của request HTTP
    public String resolveToken(HttpServletRequest request) {
        // tìm kiếm một header có tên = TOKEN_HEADER trong request
        String bearerToken = request.getHeader(TOKEN_HEADER);
        //kiểm tra xem bearerToken có bắt đầu với TOKEN_PREFIX hay không.
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            //trích xuất phần còn lại của bearerToken, bỏ đi tiền tố TOKEN_PREFIX.
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }


    //kiểm tra tính hợp lệ của một token JWT bằng cách xác định xem token đã hết hạn hay chưa
    public boolean validateClaims(Claims claims) throws AuthenticationException {
        try {
            //lấy ra thời gian hết hạn của token JWT so sánh thời gian hết hạn với thời gian hiện tại
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            throw e;
        }
    }
    public String getEmail(Claims claims) {
        return claims.getSubject();
    }
    private List<String> getRoles(Claims claims) {
        return (List<String>) claims.get("roles");
    }

}
