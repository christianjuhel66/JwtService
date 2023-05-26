package org.sid.secservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.secservice.sec.JWTUtil;
import org.sid.secservice.sec.entities.AppRole;
import org.sid.secservice.sec.entities.AppUser;
import org.sid.secservice.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path="/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping(path= "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path= "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path= "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void  addRoleToUser(@RequestBody  RoleUserForm roleUserForm){
         accountService.addRoleToUser(roleUserForm.getUserName(), roleUserForm.getRoleName());
    }

    @GetMapping(path="/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse    response) throws IOException {
        String authToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken !=null && authToken.startsWith(JWTUtil.PREFIX)){
            try{
                String jwt=authToken.substring(JWTUtil.PREFIX.length());// j'extrait juste le token du header Authoriization sassn "Bearer "
                Algorithm algorithm= Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT= jwtVerifier.verify(jwt);
                String username= decodedJWT.getSubject();
                //si j'ai une blacklist je regarde si le usrname est dans la blacklist
                AppUser appUser= accountService.loadUserByUserName(username);

                //je génère un nouvel  asccessToken
                String jwtAccessToken= JWT.create()
                        .withSubject( appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis()+ JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",  appUser.getAppRoles().stream().map(r-> r.getRoleName()).collect(Collectors.toList()))
                        .sign( algorithm);

                //j'envoie les tokens
                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
            }
            catch(Exception e){
                throw e;
            }
        }else{
               throw new RuntimeException("Refresh token is required");
        }
    }

    @GetMapping(path="/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUserName(principal.getName());
    }

}

/**ceci n'est pas une classe interne (on aurait pu la déclarer
 *   dans son propre fichier de façon classique
 */
@Data
class RoleUserForm{
          private String  userName;
          private String roleName;
    }