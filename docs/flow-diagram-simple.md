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
graph TD
    A[User Enters Credentials] --> B[POST /auth/register/challenge]
    B --> C[Generate Client Key]
    C --> D[Hash Password]
    D --> E[Create userHandle]
    E --> F[Return Challenge + Options]
    F --> G[User Creates Passkey]
    G --> H[POST /auth/register/verify]
    H --> I[Store User + Public Key]
    I --> J[Registration Complete]
```

## 2. User Authentication Flow

```mermaid
graph TD
    A[User Enters Username + Password] --> B[POST /auth/login/challenge]
    B --> C[Find User by Username]
    C --> D[Prepare allowCredentials]
    D --> E[Return Challenge]
    E --> F[User Authenticates with Passkey]
    F --> G{Passkey Available?}
    G -->|Yes| H[POST /auth/login/verify]
    G -->|No| I[New Device Detected]
    H --> J[Verify Password]
    J --> K[Verify Passkey Signature]
    K --> L[Extract Client Key from userHandle]
    L --> M[Verify Client Key Match]
    M --> N[Authentication Successful]
    I --> O[Generate QR Code]
    O --> P[Device Registration Flow]
```

## 3. Multi-Factor Authentication

```mermaid
graph TD
    A[Authentication Request] --> B[Layer 1: Password]
    B --> C[Layer 2: Passkey]
    C --> D[Layer 3: Client Key]
    D --> E[All Layers Verified]
    E --> F[Access Granted]
    
    B --> G[bcrypt hash verification]
    C --> H[WebAuthn signature verification]
    D --> I[Client key extraction from userHandle]
```

## 4. New Device Registration

```mermaid
graph TD
    A[New Device Login] --> B[WebAuthn Fails]
    B --> C[Generate QR Code]
    C --> D[Display QR Code]
    D --> E[Trusted Device Scans QR]
    E --> F[Create Authorization Passkey]
    F --> G[Authorize New Device]
    G --> H[New Device Creates Passkey]
    H --> I[Authentication Successful]
```

## 5. Data Storage Structure

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
```

## 6. Security Architecture

```mermaid
graph TD
    A[Security Layers] --> B[Password Layer]
    A --> C[Passkey Layer]
    A --> D[Client Key Layer]
    
    B --> E[bcrypt hash, 12 salt rounds]
    C --> F[Private key never leaves device]
    C --> G[Public key verification]
    D --> H[Server-generated secret]
    D --> I[Embedded in userHandle]
    
    J[Domain Security] --> K[RP_ID: prod.jeev.es]
    J --> L[Platform authenticator preference]
    J --> M[User verification required]
```

## 7. API Endpoints

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

## Key Features Summary

- **Multi-Factor Authentication**: Password + Passkey + Client Key
- **Device Management**: QR code-based new device registration
- **PIN Support**: Hardware security key integration
- **Dynamic Versioning**: Automatic version management
- **Comprehensive Logging**: Cryptographic key tracking
- **Security First**: No private key transmission
- **Browser Compatible**: Works across major browsers
- **Password Manager Ready**: Optimized for Keeper, 1Password, etc. 