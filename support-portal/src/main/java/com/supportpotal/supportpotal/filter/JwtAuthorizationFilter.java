package com.supportpotal.supportpotal.filter;

import com.supportpotal.supportpotal.constant.SecurityConstant;
import com.supportpotal.supportpotal.utility.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static com.supportpotal.supportpotal.constant.SecurityConstant.TOKEN_PREFIX;

@RequiredArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter { //한번만 실행되는 필터
    private final JWTTokenProvider jwtTokenProvider;

    @Override //필터를 통하여 토큰이 유효한지 확인 한다
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getMethod().equalsIgnoreCase(SecurityConstant.OPTIONS_HTTP_METHOD)) {
            response.setStatus(HttpStatus.OK.value()); //get post를 보내기 전에 option 메소드를 사용하여 통신이 가능한 상태인지 확인하여 ok를 보내준다.
        } else {         //get put post 등 일때
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX) ) {
                filterChain.doFilter(request, response); //계속 프로세스가 동작해라고 넣어줌 없으면 종료
                return;
            }
            String token = authorizationHeader.substring(TOKEN_PREFIX.length()); //bearer 자른 토큰 가져오기
            String username = jwtTokenProvider.getSubject(token); //username을 토큰에서 가져오기
            if(jwtTokenProvider.isTokenValid(username, token)) {
                List<GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);
                Authentication authentication = jwtTokenProvider.getAuthentication(username, authorities, request);
                SecurityContextHolder.getContext().setAuthentication(authentication); //시큐리티 컨텍스트에 인증정보 저장
            } else {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response); //다음 필터로 이동
    }
}
