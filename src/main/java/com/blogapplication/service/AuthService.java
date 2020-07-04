package com.blogapplication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import com.blogapplication.dto.LoginRequest;
import com.blogapplication.dto.RegisterRequest;
import com.blogapplication.model.User;
import com.blogapplication.repository.UserRepository;
import com.blogapplication.security.SecurityConfig;
import com.blogapplication.securityJWT.JWTProvider;

@Service
public class AuthService {
	
	@Autowired
	private UserRepository _userRepository;
	
	@Autowired
	private AuthenticationManager authetnticationmanager;
	
	@Autowired
	private BCryptPasswordEncoder encoder;
	
	 @Autowired
	 private JWTProvider jwt;
	
	public void signup(RegisterRequest registerrequest)
	{
		User user = new User();
		
		user.setUsername(registerrequest.getUsername());
		user.setPassword(PasswordEncoder(registerrequest.getPassword()));
		user.setEmail(registerrequest.getEmail());
		
		_userRepository.save(user);
	}
	
	
	
	public String PasswordEncoder(String password)
	{
		return encoder.encode(password);
	}
	
	
	public String login(@RequestBody  LoginRequest loginRequest)
	{
		Authentication authentication=   authetnticationmanager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
	    SecurityContextHolder.getContext().setAuthentication(authentication);
	   return jwt.generateToken(authentication);
	}
	

}

