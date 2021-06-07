package ir.co.isc.jwt.controller;

import ir.co.isc.jwt.model.JWTRequest;
import ir.co.isc.jwt.model.JWTResponse;
import ir.co.isc.jwt.service.UserService;
import ir.co.isc.jwt.utility.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userSErvice;

    @GetMapping("/")
    public String home(){
        return "Welcome to my first JWT application";
    }

    @PostMapping("authenticate")
    public JWTResponse authenticate(@RequestBody JWTRequest jwtRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUserName(),
                            jwtRequest.getPassword()));
        }catch (BadCredentialsException e){
            throw new Exception("INVALID-CREDENTIAL",e);
        };

        final UserDetails userDetails= userSErvice.loadUserByUsername(jwtRequest.getUserName());

        final String token=jwtUtility.generateToken(userDetails);

        return new JWTResponse(token);
    }
}
