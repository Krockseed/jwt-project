package com.example.jwt.service;

import com.example.jwt.controller.dto.MemberDTO;
import com.example.jwt.domain.Authority;
import com.example.jwt.domain.Member;
import com.example.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Member register(MemberDTO memberDTO) {
        Optional<Member> findMember = memberRepository.findByEmail(memberDTO.getEmail());

        if (findMember.isPresent()) {
            throw new RuntimeException("이미 존재하는 사용자입니다");
        }

        Member member = Member.builder()
                .email(memberDTO.getEmail())
                .password(passwordEncoder.encode(memberDTO.getPassword()))
                .authority(Authority.ROLE_USER)
                .nickname(memberDTO.getNickname()).build();

        return memberRepository.save(member);
    }

    public Member getMember(String email) {
        return memberRepository.findByEmail(email).orElseThrow(
                () -> new UsernameNotFoundException("사용자를 찾을 수 없습니다")
        );
    }
}
