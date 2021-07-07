package com.zerock.j09;

import com.zerock.j09.user.security.util.JWTUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class J09ApplicationTests {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void contextLoads() {
    }

    @Test
    public void testCreateJWT() throws Exception {

        String email = "user88@aaa.com";

        String result = new JWTUtil().generateToken(email);

        System.out.println(result);

    }

    @Test
    public void testValidate() throws Exception {
        String str = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjU2MzczMTIsImV4cCI6MTYyODIyOTMxMiwic3ViIjoidXNlcjg4QGFhYS5jb20ifQ.pXEdY33YSOxx83qk6arEyUGnNiBQkOSvbZU-1c4xsF4";

        System.out.println(new JWTUtil().validateAndExtract(str));
    }

    @Test
    public void testEncode() {
        System.out.println(passwordEncoder.encode("1111"));

        String enStr = "$2a$10$8kQa4op50rs1C3ftIYBiCeBhC/nnoO9RzArgT8COOVwvD4.l519iC";

        System.out.println(passwordEncoder.matches("1111", enStr));

    }

}
