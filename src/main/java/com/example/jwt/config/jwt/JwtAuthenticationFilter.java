package com.example.jwt.config.jwt;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리지에서 UsernamePasswordAuthenticationFilter
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    
    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("로긍니 시도중");

        //1. username,password 받아서
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println("input = " + input);
//            }
//            System.out.println(request.getInputStream().toString());

            ObjectMapper om = new ObjectMapper(); //JSON 파일을 파싱해준다.
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            //PrincipalDetailesService의 loadUserByUsername() 함수가 실행됨
            //loadUserByUsername() 실행된 후 정상이면 authentication이 리턴됨.
            //즉 DB에 있는 username과 password가 일치한다.
            //authenticationManager에 토큰을 넣어서 던지면 인증을 해준다,
            //
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session영역에 저장됨. => 출력이된다는것은 세션에서 값이 있다는것 즉,로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 = " + principalDetails.getUser().getUsername());

            //authentication 객체가 session영역에 저장을 해야하고 그방법이 return 해주면됨.
            //리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
            //굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어준다.
            return authentication;
            //authentication객체가 return 될때 session영역에 저장됨.
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //System.out.println("===============================");
        //2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시드를 하면

        //3.PrincipalDetailService가 호출 loadUserByUsername() 메소드 실행행

        //4. PricipalDetails를 세션에 담고

        //5. JWT 토큰을 만들어서 응답해주면된다.
    }

    //attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행되요.
    //JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는뜻임.");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식은 아님 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("jisu토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("jisu"));//jisu라는 키를 가지고있어야함

        response.addHeader("Authorization","Bearer "+jwtToken);
//        super.successfulAuthentication(request,response,chain,authResult);
    }
}
