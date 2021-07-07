package com.zerock.j09.user.security.filter;

import com.zerock.j09.user.security.util.JWTUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
public class ApiCheckFilter extends OncePerRequestFilter {

    private String pattern;
    private AntPathMatcher matcher;

    public ApiCheckFilter(String pattern) {
        this.pattern = pattern;
        this.matcher = new AntPathMatcher();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("ApiCheckFilter..........");
        log.info("ApiCheckFilter..........");
        log.info("ApiCheckFilter..........");

        String requestURI = request.getRequestURI();
        boolean matchResult = matcher.match(pattern, requestURI);

        if(matchResult == false) {
            log.info("passing..........................");
            filterChain.doFilter(request, response); // 필터의 마지막 동작은 다음 필터로 보내거나 넘기는 것;
            return;
        }

        log.info("check target..................");

        String tokenValue = request.getHeader("Authorization");

        log.info(tokenValue);

        if(tokenValue != null) {

            String jwtStr = tokenValue.substring(7);

            try {

                String email = new JWTUtil().validateAndExtract(jwtStr);
                log.info("============ extract result: "+email); //여기에 패스워드 넣는 것은 고민을 좀 해야 하는 방법이다.
                filterChain.doFilter(request, response);

            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                String content = "{\"msg\": \"TOKEN ERROR\"}";
                response.getWriter().println(content);
            }

        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            String content = "{\"msg\": \"TOKEN ERROR\"}";
            response.getWriter().println(content);
        }//end if else

    }
}
