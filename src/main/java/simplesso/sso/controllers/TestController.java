package simplesso.sso.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("/echo")
    public EchoInfo echoTest() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null) {
            return new EchoInfo(authentication.getName(),
                    authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        }
        return null;
    }

    public record EchoInfo(String username, List<String> roles) {

    }
}
