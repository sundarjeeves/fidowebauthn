# 🔐 FIDO2 WebAuthn Authentication Flow Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FIDO2 Passwordless Authentication System             │
│                              Version 1.1.0                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 1. User Registration Flow

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant BE as Backend
    participant PM as Password Manager
    participant Auth as Authenticator

    U->>FE: Enter username, password, displayName
    FE->>BE: POST /auth/register/challenge
    Note over BE: Generate client key (16 bytes)
    Note over BE: Hash password (bcrypt)
    Note over BE: Create userHandle: "username:clientKey"
    BE->>FE: Return challenge + clientKey + publicKey options
    
    Note over FE: Display client key to user
    Note over FE: Store in localStorage (Keeper backup)
    
    U->>FE: Click "Register User"
    FE->>Auth: navigator.credentials.create()
    Note over Auth: Generate key pair locally
    Note over Auth: Store private key securely
    Auth->>FE: Return credential with public key
    
    FE->>BE: POST /auth/register/verify
    Note over BE: Verify attestation
    Note over BE: Store user + public key + client key
    Note over BE: Register device info
    BE->>FE: Success response
    
    Note over PM: Passkey stored with:
    Note over PM: - userHandle: "username:clientKey"
    Note over PM: - displayName: clientKey
    Note over PM: - name: "username [Key: abc123...]"
```

## 2. User Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant BE as Backend
    participant PM as Password Manager
    participant Auth as Authenticator

    U->>FE: Enter username + password
    FE->>BE: POST /auth/login/challenge
    Note over BE: Find user by username
    Note over BE: Prepare allowCredentials
    BE->>FE: Return challenge + publicKey options
    
    U->>FE: Click "Authenticate"
    FE->>Auth: navigator.credentials.get()
    Note over Auth: Verify user (biometric/PIN)
    Note over Auth: Sign challenge with private key
    Auth->>FE: Return assertion
    
    FE->>BE: POST /auth/login/verify
    Note over BE: Verify password (bcrypt)
    Note over BE: Verify assertion signature
    Note over BE: Extract client key from userHandle
    Note over BE: Verify client key match
    Note over BE: Update device usage
    BE->>FE: Success + device list
    
    Note over U: Multi-factor authentication:
    Note over U: ✅ Password verified
    Note over U: ✅ Passkey verified  
    Note over U: ✅ Client key verified
```

## 3. PIN-Based Registration Flow

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant BE as Backend
    participant SK as Security Key

    U->>FE: Enter username, password, displayName
    U->>FE: Click "Register User (PIN/Security Key)"
    FE->>BE: POST /auth/register/challenge-pin
    
    Note over BE: Generate client key
    Note over BE: Hash password
    Note over BE: Set authenticatorAttachment: "cross-platform"
    BE->>FE: Return challenge + publicKey options
    
    FE->>SK: navigator.credentials.create()
    Note over SK: Prompt for PIN
    Note over SK: Generate key pair
    SK->>FE: Return credential
    
    FE->>BE: POST /auth/register/verify
    Note over BE: Verify attestation
    Note over BE: Store user with PIN flag
    BE->>FE: Success response
```

## 4. New Device Registration Flow

```mermaid
sequenceDiagram
    participant ND as New Device
    participant FE as Frontend
    participant BE as Backend
    participant TD as Trusted Device
    participant QR as QR Code

    ND->>FE: Login with username + password
    FE->>BE: POST /auth/login/challenge
    BE->>FE: Return challenge
    
    FE->>ND: WebAuthn fails (no passkey)
    FE->>BE: POST /auth/login/verify (webAuthnFailed: true)
    
    Note over BE: Detect new device
    Note over BE: Generate QR code with session
    BE->>FE: Return QR code + sessionId
    
    Note over ND: Display QR code
    Note over ND: "Scan with trusted device"
    
    TD->>QR: Scan QR code
    TD->>BE: POST /auth/device/register
    Note over BE: Generate new registration challenge
    Note over BE: For trusted device authorization
    BE->>TD: Return registration options
    
    TD->>TD: Create authorization passkey
    TD->>BE: POST /auth/device/verify
    Note over BE: Store authorization passkey
    Note over BE: Mark session as authorized
    BE->>TD: Authorization complete
    
    Note over ND: Poll for authorization status
    ND->>BE: GET /auth/device/status/:sessionId
    BE->>ND: Status: authorized
    
    ND->>BE: POST /auth/device/complete
    Note over BE: Generate registration for new device
    Note over BE: Use authorized client key
    BE->>ND: Return registration options
    
    ND->>ND: Create passkey for new device
    ND->>BE: POST /auth/register/verify
    Note over BE: Store new device passkey
    BE->>ND: Login successful
```

## 5. Cryptographic Key Flow

```mermaid
graph TD
    A[Server Start] --> B[Generate Client Key]
    B --> C[16 bytes random]
    C --> D[Hex encode: 32 chars]
    
    E[User Registration] --> F[Create userHandle]
    F --> G["username:clientKey"]
    G --> H[Base64url encode]
    
    I[Password Hashing] --> J[bcrypt hash]
    J --> K[12 salt rounds]
    
    L[WebAuthn Challenge] --> M[128 bytes random]
    M --> N[Base64url encode]
    
    O[Credential Storage] --> P[Public Key PEM]
    P --> Q[Store in users Map]
    
    R[Authentication] --> S[Extract userHandle]
    S --> T[Base64url decode]
    T --> U[Split username:clientKey]
    U --> V[Verify client key]
```

## 6. Data Storage Structure

```mermaid
graph TD
    A[In-Memory Storage] --> B[users Map]
    A --> C[challenges Map]
    A --> D[userDevices Map]
    A --> E[deviceRegistrationSessions Map]
    
    B --> F[Key: credentialId]
    B --> G[Value: User Object]
    
    G --> H[username: string]
    G --> I[clientKey: string]
    G --> J[hashedPassword: string]
    G --> K[credentials: Array]
    
    K --> L[credentialIdBase64: string]
    K --> M[publicKey: string]
    K --> N[counter: number]
    
    C --> O[Key: challengeId]
    C --> P[Value: Challenge Data]
    
    P --> Q[challenge: Buffer]
    P --> R[username: string]
    P --> S[clientKey: string]
    P --> T[timestamp: number]
```

## 7. Security Architecture

```mermaid
graph TD
    A[Security Layers] --> B[Layer 1: Password]
    A --> C[Layer 2: Passkey]
    A --> D[Layer 3: Client Key]
    
    B --> E[bcrypt hash]
    B --> F[12 salt rounds]
    
    C --> G[Private key never leaves device]
    C --> H[Public key verification]
    C --> I[Challenge-response protocol]
    
    D --> J[Server-generated secret]
    D --> K[Embedded in userHandle]
    D --> L[Stored in displayName]
    
    M[Domain Security] --> N[RP_ID: prod.jeev.es]
    M --> O[Platform authenticator preference]
    M --> P[User verification required]
    
    Q[Data Protection] --> R[No private keys transmitted]
    Q --> S[Client keys in userHandle only]
    Q --> T[Base64url encoding]
    Q --> U[Input sanitization]
```

## 8. Error Handling Flow

```mermaid
graph TD
    A[Error Scenarios] --> B[Registration Errors]
    A --> C[Authentication Errors]
    A --> D[Device Errors]
    
    B --> E[Username already exists]
    B --> F[UserHandle too long]
    B --> G[WebAuthn not supported]
    
    C --> H[User not found]
    C --> J[Password incorrect]
    C --> K[Passkey verification failed]
    C --> L[Client key mismatch]
    
    D --> M[New device detected]
    D --> N[QR code generation]
    D --> O[Device authorization timeout]
    
    P[Error Responses] --> Q[400: Bad Request]
    P --> R[401: Unauthorized]
    P --> S[500: Internal Server Error]
    
    T[Recovery Actions] --> U[Clear challenges after 5 min]
    T --> V[Fallback to stored client key]
    T --> W[Device registration flow]
```

## 9. API Endpoints Overview

```mermaid
graph LR
    A[API Endpoints] --> B[Registration]
    A --> C[Authentication]
    A --> D[Device Management]
    A --> E[Admin]
    A --> F[System]
    
    B --> G[POST /auth/register/challenge]
    B --> H[POST /auth/register/verify]
    B --> I[POST /auth/register/challenge-pin]
    
    C --> J[POST /auth/login/challenge]
    C --> K[POST /auth/login/verify]
    
    D --> L[POST /auth/device/register]
    D --> M[POST /auth/device/verify]
    D --> N[GET /auth/device/status/:sessionId]
    D --> O[POST /auth/device/complete]
    
    E --> P[GET /admin/users]
    E --> Q[GET /auth/test-client-key/:username]
    
    F --> R[GET /health]
    F --> S[GET /version]
```

## 10. Browser Compatibility

```mermaid
graph TD
    A[Browser Support] --> B[Chrome/Edge]
    A --> C[Safari]
    A --> D[Firefox]
    
    B --> E[Full WebAuthn support]
    B --> F[Platform authenticators]
    B --> G[Cross-platform authenticators]
    
    C --> H[WebAuthn support]
    C --> I[Touch ID/Face ID]
    C --> J[Requires residentKey: "required"]
    C --> K[Longer timeout needed]
    
    D --> L[WebAuthn support]
    F --> M[Platform authenticators]
    F --> N[Security keys]
    
    O[Password Manager Integration] --> P[Keeper Secret Manager]
    O --> Q[1Password]
    O --> R[Bitwarden]
    
    P --> S[Client key in displayName]
    P --> T[Partial key in name field]
    P --> U[localStorage backup]
```

---

## Key Features Summary

- **Multi-Factor Authentication**: Password + Passkey + Client Key
- **Device Management**: QR code-based new device registration
- **PIN Support**: Hardware security key integration
- **Dynamic Versioning**: Automatic version management
- **Comprehensive Logging**: Cryptographic key tracking
- **Security First**: No private key transmission
- **Browser Compatible**: Works across major browsers
- **Password Manager Ready**: Optimized for Keeper, 1Password, etc. 