
# Message Server Application - Java Backend

## Overview

This project is a Java-based server application designed to handle secure user registration, login, and message sending between users. The server utilizes **JWT** for session management and provides API endpoints to manage users and messages. This project also includes security features such as password encryption, message encryption, rate limiting, and logging to ensure the application is secure and reliable.

---

## Features

### 1. **User Management**

- **User Registration**: Allows new users to register by providing an email and password.
- **User Login**: Users can log in using their email and password to obtain a JWT token for authentication.
- **User Listing**: Implemented `/api/users` (GET) endpoint that returns a list of all registered users, displaying their email addresses.

### 2. **Messaging System**

- **View Messages**: Implemented `/api/messages` (GET) endpoint that returns a list of all messages belonging to the logged-in user.
  - The messages contain the following fields:
    - `date`: Timestamp when the message was sent (UTC).
    - `sender`: Email address of the user who sent the message.
    - `message`: The actual message content.
- **Send Message**: Implemented `/api/messages` (POST) endpoint to send a message from one user to another. The message is saved with a timestamp (UTC).

### 3. **Security Features**

- **Password Management**: Passwords are securely hashed using a strong hashing algorithm before being stored in the database. Passwords are never stored in plaintext.
- **Message Encryption**: Messages are encrypted before being stored in the database and are decrypted when retrieved by the user.
- **Rate Limiting**: Implemented rate limiting on all public API endpoints to protect against DoS (Denial-of-Service) attacks.
- **Logging**: Key events are logged, including login attempts, user actions, and rate limiting triggers.
- **Password Policy**: A strict password policy is enforced during user registration, requiring:
  - Minimum 12 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one special character
- **JWT Security**: JWT tokens are securely signed with an HS256 algorithm and include both issued and expiration dates to prevent misuse.

---

## Threat Modeling

Data flow diagrams were created using **OWASP Threat Dragon** to model the two main processes of the application:

1. **User Registration and Login**
   - The process includes user registration and login, interacting with a user database.
   - Security measures ensure that sensitive data, like passwords, are encrypted.

2. **Message Sending and Fetching**
   - This process involves sending and fetching messages between users.
   - Encryption ensures that messages are not stored in plaintext, maintaining confidentiality.

For each flow, potential threats were identified, and mitigations were proposed to secure the application against common vulnerabilities.

---

## Software Bill of Materials (SBOM)

A **Software Bill of Materials (SBOM)** was generated for the project using the **CycloneDX plugin**. This SBOM includes information about all external dependencies, their purpose, and any associated security risks.

---

## Security Report

The security mechanisms implemented in this project are described in detail in the **Security Report**, which includes:

1. **Description of Security Mechanisms**: 
   - Password hashing, message encryption, JWT security, and rate limiting have been implemented and are described in terms of their functionality and code location.
   
2. **SBOM Analysis**:
   - External dependencies used in the project have been analyzed, including their purpose, licenses, and suitability for the project.

---

## Running the Application

To run the project locally, follow these steps:

### Prerequisites

- **Java 17** or higher
- **Gradle** for build automation
- **Docker** (optional, for containerization)

### Clone the Repository

```bash
git clone https://github.com/Iara-alrawi/MessageServerApplication.git
cd MessageServerApplication

