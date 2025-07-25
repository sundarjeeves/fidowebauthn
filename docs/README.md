# 🔐 FIDO2 WebAuthn Authentication System Documentation

## 📊 Flow Diagrams

This directory contains comprehensive flow diagrams for the FIDO2 WebAuthn authentication system.

### Available Diagrams

1. **`flow-diagram.mmd`** - Main authentication flow diagram (pure Mermaid format)
2. **`authentication-flow.mmd`** - Detailed authentication process
3. **`system-architecture.mmd`** - System architecture overview
4. **`data-flow.mmd`** - Data flow through the system

### How to View

- **Mermaid Live Editor**: Copy any `.mmd` file content to https://mermaid.live
- **VS Code**: Install Mermaid extension for preview
- **GitHub**: Diagrams will render automatically in markdown files

### Quick Overview

The system implements a three-layer authentication:
1. **Password** - bcrypt hashed
2. **Passkey** - WebAuthn credential
3. **Client Key** - Server-generated secret embedded in userHandle

### Key Features

- Multi-factor authentication
- QR code-based device registration
- PIN support for hardware security keys
- Comprehensive cryptographic key logging
- Password manager integration (Keeper, 1Password, etc.)
- Dynamic version management 