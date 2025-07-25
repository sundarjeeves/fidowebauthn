# Passkey + Client Key Authentication Demo

A comprehensive FIDO2/WebAuthn authentication system with embedded client keys for enhanced security.

## Features

- 🔐 **Multi-Factor Authentication**: Username + Password + Passkey + Client Key
- 🔑 **Embedded Client Keys**: Server-generated keys stored in passkey userHandle and displayName
- 🛡️ **FIDO2/WebAuthn**: Modern passwordless authentication with biometric verification
- 📱 **Cross-Device QR Authentication**: Authenticate from one device for another
- 🎨 **Modern UI**: Clean black and beige themed interface
- ✅ **Comprehensive Testing**: Full test suite with mocks, spies, and coverage

## Security Architecture

### Authentication Flow
1. **Registration**: User provides username, password, displayName
2. **Client Key Generation**: Server generates unique 32-character hex key
3. **Passkey Creation**: Client key embedded in userHandle (`username:clientKey`) and displayName
4. **Storage**: Password hashed with bcrypt, all data stored securely

### Authentication Verification
1. **Multi-Factor Input**: Username + Password + Passkey biometric
2. **Password Verification**: bcrypt comparison against stored hash
3. **Passkey Verification**: FIDO2 cryptographic verification
4. **Client Key Extraction**: Automatic extraction from passkey userHandle
5. **Validation**: All factors must match for successful authentication

## 🔐 WebAuthn Security Architecture

### Core Security Principles

**IMPORTANT**: In WebAuthn, private keys NEVER leave the device. This is fundamental to the security model.

#### ✅ Correct Flow (Secure)
```
1. Client requests challenge from server
2. Server sends challenge + options (rp: "prod.jeev.es", platform preference)
3. Client device generates private/public key pair LOCALLY
4. Private key stays on device (never transmitted)
5. Client sends public key + signed challenge to server
6. Server stores public key and verifies signature
```

#### ❌ Insecure Flow (DO NOT DO)
```
1. Server generates private/public key pair
2. Server sends private key to client ← SECURITY VULNERABILITY
3. Server stores public key
```

### Domain Configuration

For production deployment on `prod.jeev.es`:

```bash
# Environment variables
export RP_ID="prod.jeev.es"
export RP_NAME="Jeev.es Authentication"
export RP_ICON="https://prod.jeev.es/favicon.ico"
```

### Platform Authenticator Preference

The system is configured to prefer platform authenticators:
- **Touch ID** (macOS/iOS)
- **Face ID** (iOS/iPadOS)  
- **Windows Hello** (Windows)
- **Android Biometrics** (Android)

For hardware security keys (YubiKey, etc.), use the PIN registration flow.

## 🛠️ Implementation Details

## Installation

```bash
npm install
npm start
```

Visit http://localhost:3000

## Testing

### Run All Tests
```bash
npm test
```

### Watch Mode
```bash
npm run test:watch
```

### Coverage Report
```bash
npm run test:coverage
```

## Test Suite

### 📋 Test Categories

#### **Unit Tests** (`tests/utils.test.js`)
- ✅ Client key generation and uniqueness
- ✅ Base64URL encoding/decoding
- ✅ UserHandle encoding with security limits
- ✅ Error handling for malformed data
- ✅ Unicode character support

#### **Mock Server Tests** (`tests/mock-server.test.js`)
- ✅ Complete registration flow
- ✅ Multi-factor authentication flow
- ✅ Duplicate username prevention
- ✅ Password verification
- ✅ Client key persistence
- ✅ Admin endpoint functionality
- ✅ Error scenarios and validation

#### **Security Tests** (`tests/security.test.js`)
- ✅ UserHandle 64-byte limit enforcement
- ✅ Injection attack prevention
- ✅ Base64URL encoding security
- ✅ Buffer overflow protection
- ✅ Session challenge validation
- ✅ Input sanitization
- ✅ Multi-factor requirement validation

#### **Integration Tests** (`tests/integration.test.js`)
- ✅ Server health checks
- ✅ Endpoint availability
- ✅ QR code authentication
- ✅ Admin panel functionality
- ✅ Error response validation

### 🧪 Test Features

- **Comprehensive Mocking**: FIDO2, bcrypt, crypto modules
- **Spy Functions**: Verify function calls and parameters
- **Error Scenarios**: Invalid inputs, malformed data, security attacks
- **Edge Cases**: Unicode, special characters, boundary conditions
- **Security Validation**: Injection prevention, buffer limits, encoding safety

## API Endpoints

### Authentication
- `POST /auth/register/challenge` - Start user registration
- `POST /auth/register/verify` - Complete registration with passkey
- `POST /auth/login/challenge` - Start authentication
- `POST /auth/login/verify` - Complete multi-factor authentication

### QR Authentication
- `POST /auth/qr/initiate` - Generate QR code for cross-device auth
- `GET /auth/qr/status/:sessionId` - Check authentication status
- `POST /auth/qr/complete` - Complete QR authentication
- `POST /auth/qr/verify` - Verify cross-device authentication

### Admin
- `GET /admin/users` - List registered users
- `DELETE /admin/users/:credentialId` - Delete user
- `GET /health` - Server health check

## Security Features

### 🔐 Client Key Security
- **128-bit entropy**: Cryptographically secure random generation
- **Dual storage**: Embedded in both userHandle and displayName
- **Automatic verification**: Extracted and validated on each login
- **Collision resistant**: Extremely low probability of duplicates

### 🛡️ Data Protection
- **Password hashing**: bcrypt with 12 salt rounds
- **Base64URL encoding**: Safe for URLs and HTTP headers
- **UserHandle limits**: 64-byte WebAuthn specification compliance
- **Input validation**: Comprehensive sanitization and checks

### 🔒 Authentication Security
- **Multi-factor required**: All factors must be present and valid
- **Challenge-based**: Prevents replay attacks
- **Time-limited sessions**: Automatic challenge expiration
- **Unique identifiers**: UUIDs for all challenges and sessions

## Development

### Project Structure
```
passwordless/
├── index.js              # Main server application
├── public/
│   └── index.html        # Frontend UI
├── tests/
│   ├── utils.test.js     # Utility function tests
│   ├── mock-server.test.js # Core logic tests
│   ├── security.test.js  # Security validation tests
│   └── integration.test.js # Server integration tests
└── package.json
```

### Dependencies
- **express**: Web server framework
- **fido2-lib**: FIDO2/WebAuthn implementation
- **bcrypt**: Password hashing
- **qrcode**: QR code generation for cross-device auth
- **uuid**: Unique identifier generation

### Dev Dependencies
- **jest**: Testing framework
- **supertest**: HTTP testing utilities

## Browser Compatibility

- ✅ Chrome 67+ (Windows, macOS, Android)
- ✅ Firefox 60+ (Windows, macOS)
- ✅ Safari 14+ (macOS, iOS)
- ✅ Edge 79+ (Windows)

## License

ISC 