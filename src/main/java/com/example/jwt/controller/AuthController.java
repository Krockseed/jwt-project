package com.example.jwt.controller;

import com.example.jwt.common.JwtFilter;
import com.example.jwt.common.JwtTokenProvider;
import com.example.jwt.controller.dto.LoginDTO;
import com.example.jwt.controller.dto.MemberDTO;
import com.example.jwt.controller.dto.TokenDTO;
import com.example.jwt.domain.Member;
import com.example.jwt.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MemberService memberService;

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDTO> authorize(@RequestBody LoginDTO loginDTO) {

        log.info("authenticate here! = {}", loginDTO);

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword());

        log.info("UsernamePasswordAuthenticationToken create Success = {}", token);

        Authentication authentication = authenticationManagerBuilder
                .getObject()
                .authenticate(token);
        log.info("authentication = {}", authentication);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info("SecurityContextHolder set Authentication Success!!");

        String jwt = jwtTokenProvider.createToken(authentication);


        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        log.info("create jwt success = {}", jwt);

        return new ResponseEntity<>(new TokenDTO(jwt), httpHeaders, HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<Member> signup(@RequestBody MemberDTO memberDTO) {
        return ResponseEntity.ok(memberService.register(memberDTO));
    }

    @GetMapping("/admin")
    public String admin() {
        return "your admin";
    }

    @GetMapping("/all")
    public String all(HttpServletRequest request) {
        String jwt = request.getHeader(JwtFilter.AUTHORIZATION_HEADER);
        log.info("jwt = {}", jwt);

        Authentication authentication = jwtTokenProvider.getAuthentication(jwt.substring(7));
        Member member = memberService.getMember(authentication.getName());

        return "hello " + member.getNickname();
    }
}
