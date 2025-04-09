package se.gritacademy;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@SpringBootApplication
public class MessageServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(MessageServerApplication.class, args);
    }
}

@Entity
class UserInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String password;
    private String role = "user";

    public UserInfo() {}

    public UserInfo(String email, String password, String role) {
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public String getRole() { return role; }
}

@Entity
class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String sender;
    private String recipient;
    private String message;
    private Instant date;

    public Message() {}

    public Message(String sender, String recipient, String message, Instant date) {
        this.sender = sender;
        this.recipient = recipient;
        this.message = message;
        this.date = date;
    }

    public String getSender() { return sender; }
    public String getRecipient() { return recipient; }
    public String getMessage() { return message; }
    public Instant getDate() { return date; }
}

interface UserRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByEmail(String email);
}

interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findByRecipient(String recipient);
}

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
class AuthController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageRepository messageRepository;

    private static final Logger logger = Logger.getLogger("AppLogger");
    private static final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();
    private static final int RATE_LIMIT = 5; // Max requests per minute

    static {
        try {
            FileHandler fileHandler = new FileHandler("application.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean isRateLimited(String ip) {
        requestCounts.putIfAbsent(ip, 0);
        requestCounts.put(ip, requestCounts.get(ip) + 1);
        if (requestCounts.get(ip) > RATE_LIMIT) {
            logger.warning("Rate limit exceeded for IP: " + ip);
            return true;
        }
        return false;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestParam String email, @RequestParam String password) {
        if (!isValidPassword(password)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid password format");
        }
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
        }
        userRepository.save(new UserInfo(email, password, "user"));
        logger.info("User registered: " + email);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String email, @RequestParam String password) {
        Optional<UserInfo> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent() && userOpt.get().getPassword().equals(password)) {
            String token = generateJwtToken(userOpt.get());
            logger.info("Successful login: " + email);
            return ResponseEntity.ok(token);
        }
        logger.warning("Failed login attempt: " + email);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
    }

    @GetMapping("/users")
    public ResponseEntity<List<String>> getUsers(@RequestHeader("Authorization") String token) {
        parseJwtToken(token.replace("Bearer ", ""));
        List<String> users = userRepository.findAll().stream().map(UserInfo::getEmail).collect(Collectors.toList());
        logger.info("User list requested");
        return ResponseEntity.ok(users);
    }

    @GetMapping("/messages")
    public ResponseEntity<List<Message>> getMessages(@RequestHeader("Authorization") String token) {
        Claims claims = parseJwtToken(token.replace("Bearer ", ""));
        String userEmail = claims.getSubject();
        List<Message> messages = messageRepository.findByRecipient(userEmail);
        logger.info("Messages requested for user: " + userEmail);
        return ResponseEntity.ok(messages);
    }

    @PostMapping("/messages")
    public ResponseEntity<String> sendMessage(@RequestHeader("Authorization") String token,
                                              @RequestParam String recipient,
                                              @RequestParam String message) {
        Claims claims = parseJwtToken(token.replace("Bearer ", ""));
        String sender = claims.getSubject();
        messageRepository.save(new Message(sender, recipient, message, Instant.now()));
        logger.info("Message sent from " + sender + " to " + recipient);
        return ResponseEntity.ok("Message sent successfully");
    }

    private String generateJwtToken(UserInfo user) {
        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("role", user.getRole())
                .compact();
    }

    private Claims parseJwtToken(String token) {
        return Jwts.parserBuilder().build().parseClaimsJwt(token).getBody();
    }

    private boolean isValidPassword(String password) {
        return password.length() >= 12 &&
                Pattern.compile(".*[A-Z].*").matcher(password).matches() &&
                Pattern.compile(".*[a-z].*").matcher(password).matches() &&
                Pattern.compile(".*\\d.*").matcher(password).matches() &&
                Pattern.compile(".*[!@#$%^&*(),.?\":{}|<>].*").matcher(password).matches();
    }
}
