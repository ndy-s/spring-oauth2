package ndy.spring_oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()
                && !(auth.getPrincipal() instanceof String && auth.getPrincipal().equals("anonymousUser"))) {
            return "redirect:/dashboard";
        }

        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            // Determine what type of authentication we have
            Object principal = authentication.getPrincipal();

            if (principal instanceof OAuth2User) {
                // Handle GitHub OAuth2 login
                OAuth2User oauth2User = (OAuth2User) principal;

                String login = oauth2User.getAttribute("login");
                if (login != null) {
                    model.addAttribute("name", login);
                    model.addAttribute("provider", "GitHub");
                    model.addAttribute("avatar", oauth2User.getAttribute("avatar_url"));
                } else {
                    // Generic OAuth2 fallback if GitHub-specific attributes aren't available
                    model.addAttribute("name", oauth2User.getName());
                    model.addAttribute("provider", "OAuth2");
                }
            } else if (principal instanceof UserDetails) {
                // Handle username/password login
                UserDetails userDetails = (UserDetails) principal;
                model.addAttribute("name", userDetails.getUsername());
                model.addAttribute("provider", "Form Login");
            } else {
                // Fallback for other authentication types
                model.addAttribute("name", authentication.getName());
                model.addAttribute("provider", "Other");
            }
        }

        return "dashboard";
    }
}
