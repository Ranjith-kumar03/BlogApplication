package com.blogapplication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.blogapplication.dto.LoginRequest;
import com.blogapplication.dto.RegisterRequest;
import com.blogapplication.service.AuthService;
///why
@RestController
@RequestMapping("/api/auth/")
public class AuthController {
	
	@Autowired
	private AuthService _authservice;
	
	@PostMapping("/signup")
	public ResponseEntity<HttpStatus> signup(@RequestBody RegisterRequest registerrequest)
	{
		_authservice.signup(registerrequest);
		return new ResponseEntity<HttpStatus>(HttpStatus.OK);
	}
	@PostMapping("/login")
	public String Login(@RequestBody LoginRequest loginrequest)
	{
		return _authservice.login(loginrequest);
		 
	}

}