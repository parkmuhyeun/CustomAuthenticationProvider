package com.muto.Custom.config;

import com.muto.Custom.config.auth.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        //입력한 ID, Password 조회
        String userId = token.getName();
        String userPw = (String)token.getCredentials();

        //UserDetailsService를 통해 DB에서 조회한 사용자
        UserDetailsImpl dbUser = (UserDetailsImpl) userDetailsService.loadUserByUsername(userId);

        // 비밀번호 매칭되는지 확인
        if (!passwordEncoder.matches(userPw, dbUser.getPassword())) {
            throw new BadCredentialsException(dbUser.getUsername() + "Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(dbUser, userPw, dbUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
