const express = require('express');
const path = require('path');
const { Fido2Lib } = require('fido2-lib');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment configuration for domain setup
const RP_ID = process.env.RP_ID || "localhost"; // Use "prod.jeev.es" in production
const RP_NAME = process.env.RP_NAME || "Jeev.es Authentication";
const RP_ICON = process.env.RP_ICON || "https://prod.jeev.es/favicon.ico";

console.log(`🌐 WebAuthn configured for domain: ${RP_ID}`);
console.log(`🏢 Relying Party: ${RP_NAME}`);

// FIDO2 Configuration for prod.jeev.es
const fido2 = new Fido2Lib({
    timeout: 60000,
    rpId: RP_ID, // Your domain
    rpName: RP_NAME,
    rpIcon: RP_ICON,
    challengeSize: 128,
    attestation: "none",
    cryptoParams: [-7, -257],
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "preferred"
});

// In-memory storage (use database in production)
const users = new Map(); // Key: credentialId (base64url), Value: user object with username
const challenges = new Map();
const crossDeviceSessions = new Map(); // For QR code authentication sessions
const deviceRegistrationSessions = new Map(); // For new device registration QR codes
const userDevices = new Map(); // Key: username, Value: array of devices

// Clear any existing users to fix credential ID format issues
users.clear();
console.log('🧹 Cleared existing users due to credential ID format update');

// Middleware
app.use(express.json());
app.use(express.static('public'));

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// Basic routes
app.get('/', (req, res) => {
    res.json({ 
        message: 'Passkey + Client Key Authentication Server',
        timestamp: new Date().toISOString(),
        endpoints: {
            multiFactorAuth: {
                registerChallenge: 'POST /auth/register/challenge',
                registerVerify: 'POST /auth/register/verify',
                loginChallenge: 'POST /auth/login/challenge', 
                loginVerify: 'POST /auth/login/verify'
            },
            qrCodeAuth: {
                initiate: 'POST /auth/qr/initiate',
                status: 'GET /auth/qr/status/:sessionId',
                complete: 'POST /auth/qr/complete',
                verify: 'POST /auth/qr/verify'
            }
        }
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        users: users.size,
        activeChallenges: challenges.size,
        crossDeviceSessions: crossDeviceSessions.size
    });
});

// FIDO2 Registration Endpoints

// Generate registration challenge
app.post('/auth/register/challenge', async (req, res) => {
    try {
        const { username, displayName, password, deviceName } = req.body;
        
        if (!username || !displayName || !password) {
            return res.status(400).json({ 
                error: 'Username, displayName, and password are required' 
            });
        }

        // Check if user already exists (search by username since we store by credential ID)
        const existingUser = Array.from(users.values()).find(user => user.username === username);
        if (existingUser) {
            console.log(`❌ Username "${username}" already exists!`);
            return res.status(400).json({ 
                error: 'User already exists' 
            });
        }
        
        console.log(`✅ Username "${username}" is available for registration`);

        // Hash the password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate shorter client key (16 bytes = 32 hex chars to stay within 64 byte limit)
        const clientKey = crypto.randomBytes(16).toString('hex');

        // Encode username and client key into user ID for the passkey
        // This embeds the client key directly into the WebAuthn credential
        const userIdData = `${username}:${clientKey}`;
        
        // Check if the combined length exceeds WebAuthn's 64 byte limit
        if (Buffer.byteLength(userIdData, 'utf8') > 64) {
            return res.status(400).json({ 
                error: 'Username too long. Please use a shorter username.' 
            });
        }
        
        // Create user ID buffer that will be embedded in the passkey
        const userId = Buffer.from(userIdData, 'utf8');
        
        console.log(`📋 Embedding client key in passkey for user: ${username}`);
        console.log(`🔑 Client key: ${clientKey}`);
        console.log(`📦 UserID data: ${userIdData} (${Buffer.byteLength(userIdData, 'utf8')} bytes)`);
        console.log(`📝 DisplayName will contain client key: ${clientKey}`);

        // Generate registration options
        const registrationOptions = await fido2.attestationOptions();
        
        // Store challenge temporarily (keep original binary format)
        const challengeId = crypto.randomUUID();
        challenges.set(challengeId, {
            challenge: registrationOptions.challenge,
            username,
            displayName,
            deviceName: deviceName || 'Primary Device',
            hashedPassword,
            clientKey,
            userId: userId.toString('base64url'),
            userIdData,
            timestamp: Date.now()
        });

        // Clean up old challenges (older than 5 minutes)
        const now = Date.now();
        for (const [id, data] of challenges.entries()) {
            if (now - data.timestamp > 300000) {
                challenges.delete(id);
            }
        }

        // Convert challenge to base64url for client
        const challengeBase64url = Buffer.from(registrationOptions.challenge).toString('base64url');

        res.json({
            challengeId,
            clientKey, // Return the generated client key
            publicKey: {
                ...registrationOptions,
                challenge: challengeBase64url,
                rp: {
                    name: RP_NAME,
                    id: RP_ID
                },
                user: {
                    id: userId.toString('base64url'),
                    name: `${username} [Key: ${clientKey.substring(0, 8)}...]`, // Include partial key in name for Keeper visibility
                    displayName: clientKey // Store the actual client key in displayName
                },
                excludeCredentials: [],
                // Platform authenticator preference for prod.jeev.es
                authenticatorSelection: {
                    authenticatorAttachment: "platform", // Prefer platform authenticators (Touch ID, Face ID, Windows Hello)
                    userVerification: "required",
                    residentKey: "required"  // Safari prefers residentKey over requireResidentKey
                },
                timeout: 60000 // Give Safari more time
            }
        });
    } catch (error) {
        console.error('Registration challenge error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Generate registration challenge with PIN requirement
app.post('/auth/register/challenge-pin', async (req, res) => {
    try {
        const { username, displayName, password, deviceName } = req.body;
        
        if (!username || !displayName || !password) {
            return res.status(400).json({ 
                error: 'Username, display name, and password are required' 
            });
        }

        // Check for existing user
        const existingUser = Array.from(users.values()).find(user => user.username === username);
        if (existingUser) {
            console.log(`❌ Username "${username}" already exists!`);
            return res.status(400).json({ 
                error: 'User already exists' 
            });
        }
        
        console.log(`✅ Username "${username}" is available for PIN-based registration`);

        // Hash the password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate client key
        const clientKey = crypto.randomBytes(16).toString('hex');

        // Encode username and client key into user ID
        const userIdData = `${username}:${clientKey}`;
        
        if (Buffer.byteLength(userIdData, 'utf8') > 64) {
            return res.status(400).json({ 
                error: 'Username too long. Please use a shorter username.' 
            });
        }
        
        const userId = Buffer.from(userIdData, 'utf8');
        
        console.log(`🔢 PIN-based registration for user: ${username}`);
        console.log(`🔑 Client key: ${clientKey}`);

        // Generate registration options for PIN-based authenticators
        const registrationOptions = await fido2.attestationOptions();
        
        const challengeId = crypto.randomUUID();
        challenges.set(challengeId, {
            challenge: registrationOptions.challenge,
            username,
            displayName,
            deviceName: deviceName || 'PIN Security Key',
            hashedPassword,
            clientKey,
            userId: userId.toString('base64url'),
            userIdData,
            timestamp: Date.now()
        });

        const challengeBase64url = Buffer.from(registrationOptions.challenge).toString('base64url');

        res.json({
            challengeId,
            clientKey,
            publicKey: {
                ...registrationOptions,
                challenge: challengeBase64url,
                rp: {
                    name: RP_NAME,
                    id: RP_ID
                },
                user: {
                    id: userId.toString('base64url'),
                    name: `${username} [Key: ${clientKey.substring(0, 8)}...]`, // Include partial key in name for Keeper visibility
                    displayName: clientKey
                },
                excludeCredentials: [],
                // PIN-based authenticator selection for prod.jeev.es
                authenticatorSelection: {
                    authenticatorAttachment: "cross-platform", // Hardware security keys
                    userVerification: "required", // PIN required
                    residentKey: "required" // Store credential on authenticator
                },
                timeout: 60000
            }
        });
    } catch (error) {
        console.error('PIN registration challenge error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Verify registration
app.post('/auth/register/verify', async (req, res) => {
    try {
        const { challengeId, credential } = req.body;
        
        if (!challengeId || !credential) {
            return res.status(400).json({ 
                error: 'Challenge ID and credential are required' 
            });
        }

        // Get challenge data
        const challengeData = challenges.get(challengeId);
        if (!challengeData) {
            return res.status(400).json({ 
                error: 'Invalid or expired challenge' 
            });
        }

        // Helper function to convert base64url to ArrayBuffer properly (Node.js version)
        function base64urlToArrayBuffer(base64url) {
            // Convert base64url to base64
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
            
            // Use Buffer to decode base64, then convert to ArrayBuffer
            const buffer = Buffer.from(padded, 'base64');
            
            // Create a new ArrayBuffer and copy data
            const arrayBuffer = new ArrayBuffer(buffer.length);
            const view = new Uint8Array(arrayBuffer);
            for (let i = 0; i < buffer.length; i++) {
                view[i] = buffer[i];
            }
            
            return arrayBuffer;
        }

        // Log incoming credential for debugging
        console.log('Incoming credential structure:', {
            id: typeof credential.id,
            rawId: typeof credential.rawId,
            response: {
                clientDataJSON: typeof credential.response.clientDataJSON,
                attestationObject: typeof credential.response.attestationObject
            }
        });

        // Convert credential data to proper ArrayBuffers
        const credentialForVerification = {
            id: base64urlToArrayBuffer(credential.id),
            rawId: base64urlToArrayBuffer(credential.rawId),
            response: {
                clientDataJSON: base64urlToArrayBuffer(credential.response.clientDataJSON),
                attestationObject: base64urlToArrayBuffer(credential.response.attestationObject)
            },
            type: credential.type
        };

        // Log converted credential for debugging
        console.log('Converted credential structure:', {
            id: credentialForVerification.id.constructor.name,
            rawId: credentialForVerification.rawId.constructor.name,
            isArrayBuffer_id: credentialForVerification.id instanceof ArrayBuffer,
            isArrayBuffer_rawId: credentialForVerification.rawId instanceof ArrayBuffer,
            response: {
                clientDataJSON: credentialForVerification.response.clientDataJSON.constructor.name,
                attestationObject: credentialForVerification.response.attestationObject.constructor.name
            }
        });

        // Verify registration
        const attestationExpectations = {
            challenge: challengeData.challenge,
            origin: `http://localhost:${PORT}`,
            factor: "either"
        };

        // Handle new device registration
        if (challengeData.isNewDeviceRegistration) {
            const regResult = await fido2.attestationResult(credentialForVerification, attestationExpectations);
            const credentialId = regResult.authnrData.get("credId");
            const credentialIdBase64 = Buffer.from(credentialId).toString('base64url');
            
            // Find existing user to get password hash
            const existingUser = Array.from(users.values()).find(u => u.username === challengeData.username);
            if (!existingUser) {
                return res.status(400).json({ error: 'User not found' });
            }
            
            // Store new device credential for the user
            users.set(credentialIdBase64, {
                id: challengeData.userId,
                username: challengeData.username,
                displayName: challengeData.displayName,
                hashedPassword: existingUser.hashedPassword, // Use existing password hash
                clientKey: challengeData.clientKey,
                userIdData: challengeData.userIdData,
                createdAt: new Date().toISOString(),
                credentials: [{
                    credentialId: credentialId,
                    credentialIdBase64: credentialIdBase64,
                    publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
                    counter: regResult.authnrData.get("counter"),
                    createdAt: new Date().toISOString()
                }]
            });
            
            // Add device to user's device list
            const deviceInfo = {
                deviceId: crypto.randomUUID(),
                credentialId: credentialIdBase64,
                deviceName: challengeData.deviceName || 'New Device',
                userAgent: req.headers['user-agent'] || 'Unknown',
                ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
                registeredAt: new Date().toISOString(),
                lastUsed: new Date().toISOString(),
                registrationType: 'device-registration'
            };
            
            if (!userDevices.has(challengeData.username)) {
                userDevices.set(challengeData.username, []);
            }
            userDevices.get(challengeData.username).push(deviceInfo);
            
            console.log(`📱 New device registered for user ${challengeData.username}: ${deviceInfo.deviceName} (${deviceInfo.deviceId})`);
            
            // Clean up registration session
            if (challengeData.registrationSessionId) {
                deviceRegistrationSessions.delete(challengeData.registrationSessionId);
            }
            challenges.delete(challengeId);
            
            return res.json({
                success: true,
                message: 'New device registration successful',
                userId: challengeData.userId,
                clientKey: challengeData.clientKey,
                deviceInfo: {
                    deviceId: deviceInfo.deviceId,
                    deviceName: deviceInfo.deviceName,
                    registeredAt: deviceInfo.registeredAt
                }
            });
        }
        
        const regResult = await fido2.attestationResult(credentialForVerification, attestationExpectations);
        
        // Store user credentials using credential ID as key
        const credentialId = regResult.authnrData.get("credId");
        const credentialIdBase64 = Buffer.from(credentialId).toString('base64url');
        
        console.log(`💾 Storing user with embedded client key data`);
        console.log(`🔑 Credential ID (ArrayBuffer):`, credentialId);
        console.log(`🔑 Credential ID (base64url): ${credentialIdBase64}`);
        console.log(`👤 User data contains: ${challengeData.userIdData}`);
        
        users.set(credentialIdBase64, {
            id: challengeData.userId,
            username: challengeData.username,
            displayName: challengeData.displayName,
            hashedPassword: challengeData.hashedPassword,
            clientKey: challengeData.clientKey,
            userIdData: challengeData.userIdData, // Store the encoded username:clientKey
            createdAt: new Date().toISOString(),
            credentials: [{
                credentialId: credentialId,
                credentialIdBase64: credentialIdBase64, // Store both formats
                publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
                counter: regResult.authnrData.get("counter"),
                createdAt: new Date().toISOString()
            }]
        });
        
        // Track devices for this user
        const deviceInfo = {
            deviceId: crypto.randomUUID(),
            credentialId: credentialIdBase64,
            deviceName: challengeData.deviceName || 'Primary Device',
            userAgent: req.headers['user-agent'] || 'Unknown',
            ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
            registeredAt: new Date().toISOString(),
            lastUsed: new Date().toISOString()
        };
        
        if (!userDevices.has(challengeData.username)) {
            userDevices.set(challengeData.username, []);
        }
        userDevices.get(challengeData.username).push(deviceInfo);
        
        console.log(`📱 Device registered for user ${challengeData.username}: ${deviceInfo.deviceName} (${deviceInfo.deviceId})`);
        
        console.log(`✅ User stored with key: ${credentialIdBase64}`);

        // Clean up challenge
        challenges.delete(challengeId);

        res.json({
            success: true,
            message: 'Registration successful',
            userId: challengeData.userId,
            clientKey: challengeData.clientKey
        });
    } catch (error) {
        console.error('Registration verification error:', error);
        res.status(400).json({ 
            error: 'Registration verification failed' 
        });
    }
});

// FIDO2 Authentication Endpoints

// Generate authentication challenge
app.post('/auth/login/challenge', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ 
                error: 'Username is required' 
            });
        }
        
        // Find user by username
        const user = Array.from(users.values()).find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ 
                error: 'User not found' 
            });
        }
        
        // Generate authentication options with user verification required
        const authOptions = await fido2.assertionOptions();
        
        // Store challenge temporarily (keep original binary format)
        const challengeId = crypto.randomUUID();
        challenges.set(challengeId, {
            challenge: authOptions.challenge,
            username,
            timestamp: Date.now()
        });

        // Prepare allowed credentials for this specific user
        const allowCredentials = [];
        if (user.credentials && user.credentials.length > 0) {
            user.credentials.forEach(cred => {
                allowCredentials.push({
                    id: cred.credentialIdBase64,
                    type: "public-key",
                    transports: ["internal", "hybrid"]
                });
            });
        }
        
        console.log(`🔑 Prepared ${allowCredentials.length} credentials for authentication`);
        console.log(`📋 Credential IDs being sent:`, allowCredentials.map(c => c.id));

        // Convert challenge to base64url for client
        const challengeBase64url = Buffer.from(authOptions.challenge).toString('base64url');

        res.json({
            challengeId,
            publicKey: {
                ...authOptions,
                challenge: challengeBase64url,
                allowCredentials,
                // Ensure user verification is required to get userHandle back
                userVerification: "required"
            }
        });
    } catch (error) {
        console.error('Authentication challenge error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Verify authentication
app.post('/auth/login/verify', async (req, res) => {
    try {
        const { challengeId, username, password, credential, webAuthnFailed } = req.body;
        
        if (!challengeId || !username || !password) {
            return res.status(400).json({ 
                error: 'Challenge ID, username, and password are required' 
            });
        }
        
        // If WebAuthn failed on the client side, this indicates a new device
        if (webAuthnFailed || !credential) {
            console.log(`🚨 WebAuthn failed or no credential - this is definitely a new device`);
            console.log(`📱 Initiating device registration flow for user: ${username}`);
            
            // Generate device registration QR code
            const registrationSessionId = crypto.randomUUID();
            const deviceRegistrationData = {
                action: 'registerDevice',
                username: username,
                serverUrl: `http://localhost:${PORT}`,
                sessionId: registrationSessionId,
                timestamp: Date.now()
            };
            
            deviceRegistrationSessions.set(registrationSessionId, {
                username: username,
                clientKey: user.clientKey,
                newDeviceInfo: {
                    userAgent: req.headers['user-agent'] || 'Unknown',
                    ipAddress: req.ip || req.connection.remoteAddress || 'Unknown'
                },
                timestamp: Date.now(),
                status: 'pending'
            });
            
            // Generate QR code for device registration
            const qrCodeDataUrl = await QRCode.toDataURL(JSON.stringify(deviceRegistrationData));
            
            // Auto-expire sessions after 5 minutes
            setTimeout(() => {
                if (deviceRegistrationSessions.has(registrationSessionId)) {
                    deviceRegistrationSessions.delete(registrationSessionId);
                    console.log(`⏱️ Device registration session expired: ${registrationSessionId}`);
                }
            }, 5 * 60 * 1000);
            
            console.log(`📱 Device registration QR code generated for session: ${registrationSessionId}`);
            
            return res.json({
                requiresDeviceRegistration: true,
                message: 'New device detected. Please scan QR code from trusted device to register this device.',
                deviceRegistration: {
                    sessionId: registrationSessionId,
                    qrCodeDataUrl: qrCodeDataUrl,
                    qrData: deviceRegistrationData,
                    expiresAt: Date.now() + (5 * 60 * 1000)
                }
            });
        }

        // Get challenge data
        const challengeData = challenges.get(challengeId);
        if (!challengeData) {
            return res.status(400).json({ 
                error: 'Invalid or expired challenge' 
            });
        }
        
        // Verify username matches challenge
        if (challengeData.username !== username) {
            return res.status(400).json({ 
                error: 'Username mismatch' 
            });
        }

        // Get user data by credential ID
        const credentialId = credential.id;
        console.log(`🔍 Looking up user by credential ID: ${credentialId.substring(0, 16)}...`);
        console.log(`📋 Credential ID type: ${typeof credentialId}, length: ${credentialId.length}`);
        
        const user = users.get(credentialId);
        if (!user) {
            console.log(`❌ User not found for credential ID: ${credentialId}`);
            console.log(`📋 Available credential IDs:`, Array.from(users.keys()).map(id => ({ 
                short: id.substring(0, 16) + '...', 
                full: id,
                matches: id === credentialId
            })));
            return res.status(400).json({ 
                error: 'User not found' 
            });
        }
        
        console.log(`✅ Found user: ${user.username} with stored client key: ${user.clientKey}`);
        
                // Verify password
        console.log(`🔍 Verifying password for user: ${username}`);
        const passwordMatch = await bcrypt.compare(password, user.hashedPassword);
        if (!passwordMatch) {
            console.log(`❌ Password verification failed for user: ${username}`);
            return res.status(400).json({ 
                error: 'Invalid password' 
            });
        }
        console.log(`✅ Password verified successfully for user: ${username}`);
        
        // Check if this might be a new device (no credential provided or no client key in credential)
        if (!credential) {
            console.log(`🚨 No credential provided - this is a new device without any passkey`);
            console.log(`📱 Initiating device registration flow for user: ${username}`);
            
            // Generate device registration QR code
            const registrationSessionId = crypto.randomUUID();
            const deviceRegistrationData = {
                action: 'registerDevice',
                username: username,
                serverUrl: `http://localhost:${PORT}`,
                sessionId: registrationSessionId,
                timestamp: Date.now()
            };
            
            deviceRegistrationSessions.set(registrationSessionId, {
                username: username,
                clientKey: user.clientKey,
                newDeviceInfo: {
                    userAgent: req.headers['user-agent'] || 'Unknown',
                    ipAddress: req.ip || req.connection.remoteAddress || 'Unknown'
                },
                timestamp: Date.now(),
                status: 'pending'
            });
            
            // Generate QR code for device registration
            const qrCodeDataUrl = await QRCode.toDataURL(JSON.stringify(deviceRegistrationData));
            
            // Auto-expire sessions after 5 minutes
            setTimeout(() => {
                if (deviceRegistrationSessions.has(registrationSessionId)) {
                    deviceRegistrationSessions.delete(registrationSessionId);
                    console.log(`⏱️ Device registration session expired: ${registrationSessionId}`);
                }
            }, 5 * 60 * 1000);
            
            console.log(`📱 Device registration QR code generated for session: ${registrationSessionId}`);
            
            return res.json({
                requiresDeviceRegistration: true,
                message: 'New device detected. Please scan QR code from trusted device to register this device.',
                deviceRegistration: {
                    sessionId: registrationSessionId,
                    qrCodeDataUrl: qrCodeDataUrl,
                    qrData: deviceRegistrationData,
                    expiresAt: Date.now() + (5 * 60 * 1000)
                }
            });
        }
        
        // Also check if credential exists but has no userHandle (edge case)
        if (!credential.response || !credential.response.userHandle) {
            console.log(`🚨 Credential provided but no userHandle - might be an incomplete passkey`);
            console.log(`📱 Initiating device registration flow for user: ${username}`);
            
            // Generate device registration QR code
            const registrationSessionId = crypto.randomUUID();
            const deviceRegistrationData = {
                action: 'registerDevice',
                username: username,
                serverUrl: `http://localhost:${PORT}`,
                sessionId: registrationSessionId,
                timestamp: Date.now()
            };
            
            deviceRegistrationSessions.set(registrationSessionId, {
                username: username,
                clientKey: user.clientKey,
                newDeviceInfo: {
                    userAgent: req.headers['user-agent'] || 'Unknown',
                    ipAddress: req.ip || req.connection.remoteAddress || 'Unknown'
                },
                timestamp: Date.now(),
                status: 'pending'
            });
            
            // Generate QR code for device registration
            const qrCodeDataUrl = await QRCode.toDataURL(JSON.stringify(deviceRegistrationData));
            
            // Auto-expire sessions after 5 minutes
            setTimeout(() => {
                if (deviceRegistrationSessions.has(registrationSessionId)) {
                    deviceRegistrationSessions.delete(registrationSessionId);
                    console.log(`⏱️ Device registration session expired: ${registrationSessionId}`);
                }
            }, 5 * 60 * 1000);
            
            console.log(`📱 Device registration QR code generated for session: ${registrationSessionId}`);
            
            return res.json({
                requiresDeviceRegistration: true,
                message: 'Incomplete passkey detected. Please scan QR code from trusted device to register this device.',
                deviceRegistration: {
                    sessionId: registrationSessionId,
                    qrCodeDataUrl: qrCodeDataUrl,
                    qrData: deviceRegistrationData,
                    expiresAt: Date.now() + (5 * 60 * 1000)
                }
            });
        }
        
        // Update device last used time
        const devices = userDevices.get(username) || [];
        const device = devices.find(d => d.credentialId === credentialId);
        if (device) {
            device.lastUsed = new Date().toISOString();
            device.ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
            console.log(`📱 Updated device usage: ${device.deviceName} (${device.deviceId})`);
        }
        
        // Find matching credential
        console.log(`🔍 Looking for credential in user data...`);
        console.log(`📋 User has ${user.credentials.length} credentials`);
        
        const userCredential = user.credentials.find(cred => {
            const credMatches = cred.credentialId.equals ? 
                cred.credentialId.equals(Buffer.from(credential.id, 'base64url')) :
                cred.credentialIdBase64 === credential.id;
            console.log(`🔍 Checking credential: ${cred.credentialIdBase64 || 'no base64'} vs ${credential.id} = ${credMatches}`);
            return credMatches;
        });

        if (!userCredential) {
            return res.status(400).json({ 
                error: 'Credential not found' 
            });
        }

        // Debug credential data before conversion
        console.log(`🔍 Debug credential data:`, {
            clientDataJSON: {
                value: credential.response.clientDataJSON.substring(0, 100) + '...',
                length: credential.response.clientDataJSON.length,
                type: typeof credential.response.clientDataJSON
            },
            authenticatorData: {
                length: credential.response.authenticatorData.length,
                type: typeof credential.response.authenticatorData
            }
        });
        
        // Test decode clientDataJSON to see if it's valid
        try {
            const testClientData = Buffer.from(credential.response.clientDataJSON, 'base64url').toString('utf8');
            console.log(`📦 Test decoded clientDataJSON: ${testClientData.substring(0, 100)}...`);
        } catch (error) {
            console.error(`❌ Error test decoding clientDataJSON:`, error);
        }
        
        // Helper function to create properly sized ArrayBuffer from base64url
        function base64urlToArrayBuffer(base64url) {
            const buffer = Buffer.from(base64url, 'base64url');
            const arrayBuffer = new ArrayBuffer(buffer.length);
            const view = new Uint8Array(arrayBuffer);
            for (let i = 0; i < buffer.length; i++) {
                view[i] = buffer[i];
            }
            return arrayBuffer;
        }
        
        // Convert credential data from base64url strings to properly sized ArrayBuffers  
        const credentialForVerification = {
            id: base64urlToArrayBuffer(credential.id),
            rawId: base64urlToArrayBuffer(credential.rawId),
            response: {
                clientDataJSON: base64urlToArrayBuffer(credential.response.clientDataJSON),
                authenticatorData: base64urlToArrayBuffer(credential.response.authenticatorData),
                signature: base64urlToArrayBuffer(credential.response.signature),
                userHandle: credential.response.userHandle ? base64urlToArrayBuffer(credential.response.userHandle) : null
            },
            type: credential.type
        };
        
        // Debug the converted ArrayBuffer to see if corruption happens here
        console.log(`🔍 After ArrayBuffer conversion:`, {
            clientDataJSON: {
                byteLength: credentialForVerification.response.clientDataJSON.byteLength,
                type: typeof credentialForVerification.response.clientDataJSON
            },
            authenticatorData: {
                byteLength: credentialForVerification.response.authenticatorData.byteLength,
                type: typeof credentialForVerification.response.authenticatorData
            }
        });
        
        // Test if we can read back the clientDataJSON from ArrayBuffer
        try {
            const testReadBack = Buffer.from(credentialForVerification.response.clientDataJSON).toString('utf8');
            console.log(`📦 ArrayBuffer readback test: ${testReadBack.substring(0, 100)}...`);
        } catch (error) {
            console.error(`❌ Error reading back from ArrayBuffer:`, error);
        }

        // Debug the raw credential data first
        console.log(`🔍 Raw credential.response.userHandle from client:`, {
            value: credential.response.userHandle,
            type: typeof credential.response.userHandle,
            length: credential.response.userHandle ? credential.response.userHandle.length : 0
        });
        
        // Extract username and client key from the passkey's userHandle
        let extractedUsername, extractedClientKey;
        
        console.log(`🔍 Checking for userHandle in credential response...`);
        
        // FIX: Handle userHandle properly - it comes as base64url string from client
        if (credential.response.userHandle && credential.response.userHandle.length > 0) {
            try {
                // Decode base64url string directly to text
                const userHandleText = Buffer.from(credential.response.userHandle, 'base64url').toString('utf8');
                console.log(`📦 Decoded userHandle data: "${userHandleText}"`);
                console.log(`📦 UserHandle length: ${userHandleText.length} characters`);
                
                [extractedUsername, extractedClientKey] = userHandleText.split(':');
                
                console.log(`🔓 Extracted from passkey - Username: "${extractedUsername}", Client Key: "${extractedClientKey}"`);
                
                // Verify extracted data matches stored data
                if (extractedUsername !== user.username || extractedClientKey !== user.clientKey) {
                    console.log(`❌ Mismatch! Stored: ${user.username}:${user.clientKey}, Extracted: ${extractedUsername}:${extractedClientKey}`);
                    return res.status(400).json({ 
                        error: 'Invalid credential data - client key mismatch' 
                    });
                }
                
                console.log(`✅ Client key from passkey verified successfully`);
            } catch (error) {
                console.error(`❌ Error decoding userHandle:`, error);
                console.log(`⚠️ Falling back to stored client key from displayName`);
                extractedUsername = user.username;
                extractedClientKey = user.clientKey;
            }
        } else {
            console.log(`⚠️ No userHandle in credential, using client key from displayName instead`);
            console.log(`📋 Client key should be in displayName: ${user.clientKey}`);
            // Use stored client key from displayName
            extractedUsername = user.username;
            extractedClientKey = user.clientKey;
        }

        // Verify authentication
        const assertionExpectations = {
            challenge: challengeData.challenge,
            origin: `http://localhost:${PORT}`,
            factor: "either",
            publicKey: userCredential.publicKey,
            prevCounter: userCredential.counter,
            userHandle: user.id
        };

        const authResult = await fido2.assertionResult(credentialForVerification, assertionExpectations);
        
        // Update counter
        userCredential.counter = authResult.authnrData.get("counter");
        
        // Clean up challenge
        challenges.delete(challengeId);

        // Log all devices for this user
        const userDeviceList = userDevices.get(username) || [];
        console.log(`📱 All devices for user ${username}:`);
        userDeviceList.forEach((device, index) => {
            console.log(`   ${index + 1}. ${device.deviceName} (${device.deviceId})`);
            console.log(`      🔗 Credential: ${device.credentialId.substring(0, 16)}...`);
            console.log(`      📅 Registered: ${device.registeredAt}`);
            console.log(`      🕒 Last Used: ${device.lastUsed}`);
            console.log(`      🌐 IP: ${device.ipAddress}`);
            console.log(`      🖥️  User Agent: ${device.userAgent.substring(0, 50)}...`);
        });
        
        res.json({
            success: true,
            message: 'Authentication successful',
            user: {
                id: user.id,
                username: extractedUsername,
                displayName: user.displayName,
                clientKey: extractedClientKey
            },
            devices: userDeviceList.map(device => ({
                deviceId: device.deviceId,
                deviceName: device.deviceName,
                lastUsed: device.lastUsed,
                registeredAt: device.registeredAt
            }))
        });
    } catch (error) {
        console.error('Authentication verification error:', error);
        res.status(400).json({ 
            error: 'Authentication verification failed' 
        });
    }
});

// Device Registration Endpoints

// Create authorization passkey for device registration from trusted device
app.post('/auth/device/register', async (req, res) => {
    try {
        const { sessionId, username } = req.body;
        
        if (!sessionId || !username) {
            return res.status(400).json({ 
                error: 'Session ID and username are required' 
            });
        }
        
        const registrationSession = deviceRegistrationSessions.get(sessionId);
        if (!registrationSession) {
            return res.status(400).json({ 
                error: 'Invalid or expired registration session' 
            });
        }
        
        if (registrationSession.username !== username) {
            return res.status(400).json({ 
                error: 'Username mismatch' 
            });
        }
        
        // Find user to get their client key
        const user = Array.from(users.values()).find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        
        // Generate REGISTRATION challenge for creating a NEW passkey on trusted device
        const userIdData = `${username}:${user.clientKey}`;
        const userId = Buffer.from(userIdData, 'utf8');
        
        const registrationOptions = await fido2.attestationOptions();
        const challengeId = crypto.randomUUID();
        
        challenges.set(challengeId, {
            challenge: registrationOptions.challenge,
            username,
            displayName: `${username} - Authorization Device`,
            deviceName: 'Authorization Device',
            clientKey: user.clientKey,
            userId: userId.toString('base64url'),
            userIdData,
            sessionId: sessionId, // Link to device registration session
            isDeviceRegistrationAuthorization: true, // New flag for authorization passkey
            timestamp: Date.now()
        });
        
        // Get existing credentials to exclude them (force creation of new passkey)
        const excludeCredentials = [];
        const userDeviceList = userDevices.get(username) || [];
        userDeviceList.forEach(device => {
            const deviceUser = users.get(device.credentialId);
            if (deviceUser && deviceUser.credentials) {
                deviceUser.credentials.forEach(cred => {
                    excludeCredentials.push({
                        id: cred.credentialIdBase64,
                        type: "public-key"
                    });
                });
            }
        });
        
        console.log(`📱 Device registration authorization challenge generated for session: ${sessionId}`);
        console.log(`🔑 Creating NEW passkey for authorization (excluding ${excludeCredentials.length} existing credentials)`);
        
        const challengeBase64url = Buffer.from(registrationOptions.challenge).toString('base64url');
        
        res.json({
            challengeId,
            sessionId,
            registrationOptions: {
                ...registrationOptions,
                challenge: challengeBase64url,
                user: {
                    id: userId.toString('base64url'),
                    name: username,
                    displayName: user.clientKey // Store client key in displayName
                },
                excludeCredentials,
                authenticatorSelection: {
                    userVerification: "required",
                    residentKey: "required"
                },
                timeout: 60000
            }
        });
    } catch (error) {
        console.error('Device registration authorization challenge error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify device registration authorization with new passkey from trusted device
app.post('/auth/device/verify', async (req, res) => {
    try {
        const { challengeId, credential, newDeviceName, isNewPasskeyAuthorization } = req.body;
        
        if (!challengeId || !credential) {
            return res.status(400).json({ 
                error: 'Challenge ID and credential are required' 
            });
        }
        
        const challengeData = challenges.get(challengeId);
        if (!challengeData || !challengeData.isDeviceRegistrationAuthorization) {
            return res.status(400).json({ 
                error: 'Invalid or expired device registration authorization challenge' 
            });
        }
        
        const registrationSession = deviceRegistrationSessions.get(challengeData.sessionId);
        if (!registrationSession) {
            return res.status(400).json({ 
                error: 'Registration session expired' 
            });
        }
        
        // Handle NEW passkey authorization (when scanning QR code creates new passkey)
        if (isNewPasskeyAuthorization) {
            console.log(`📱 Processing NEW passkey authorization for device registration`);
            
            // Helper function for ArrayBuffer conversion
            function base64urlToArrayBuffer(base64url) {
                const buffer = Buffer.from(base64url, 'base64url');
                const arrayBuffer = new ArrayBuffer(buffer.length);
                const view = new Uint8Array(arrayBuffer);
                for (let i = 0; i < buffer.length; i++) {
                    view[i] = buffer[i];
                }
                return arrayBuffer;
            }
            
            // Convert registration credential for verification
            const credentialForVerification = {
                id: base64urlToArrayBuffer(credential.id),
                rawId: base64urlToArrayBuffer(credential.rawId),
                response: {
                    clientDataJSON: base64urlToArrayBuffer(credential.response.clientDataJSON),
                    attestationObject: base64urlToArrayBuffer(credential.response.attestationObject)
                },
                type: credential.type
            };
            
            const attestationExpectations = {
                challenge: challengeData.challenge,
                origin: `http://localhost:${PORT}`,
                factor: "either"
            };
            
            // Verify the new passkey registration
            const regResult = await fido2.attestationResult(credentialForVerification, attestationExpectations);
            const credentialId = regResult.authnrData.get("credId");
            const credentialIdBase64 = Buffer.from(credentialId).toString('base64url');
            
            // Find existing user data to get password hash
            const existingUser = Array.from(users.values()).find(u => u.username === challengeData.username);
            if (!existingUser) {
                return res.status(400).json({ error: 'User not found' });
            }
            
            // Store the NEW authorization passkey
            users.set(credentialIdBase64, {
                id: challengeData.userId,
                username: challengeData.username,
                displayName: challengeData.displayName,
                hashedPassword: existingUser.hashedPassword,
                clientKey: challengeData.clientKey,
                userIdData: challengeData.userIdData,
                createdAt: new Date().toISOString(),
                credentials: [{
                    credentialId: credentialId,
                    credentialIdBase64: credentialIdBase64,
                    publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
                    counter: regResult.authnrData.get("counter"),
                    createdAt: new Date().toISOString()
                }]
            });
            
            // Add the authorization device to user's device list
            const authDeviceInfo = {
                deviceId: crypto.randomUUID(),
                credentialId: credentialIdBase64,
                deviceName: newDeviceName || 'Authorization Device',
                userAgent: req.headers['user-agent'] || 'Unknown',
                ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
                registeredAt: new Date().toISOString(),
                lastUsed: new Date().toISOString(),
                registrationType: 'authorization-device'
            };
            
            if (!userDevices.has(challengeData.username)) {
                userDevices.set(challengeData.username, []);
            }
            userDevices.get(challengeData.username).push(authDeviceInfo);
            
            // Mark registration session as completed
            registrationSession.status = 'completed';
            registrationSession.completedAt = new Date().toISOString();
            registrationSession.authorizationDeviceId = authDeviceInfo.deviceId;
            
            console.log(`✅ Device registration authorized with NEW passkey`);
            console.log(`🔑 Authorization device registered: ${authDeviceInfo.deviceName} (${authDeviceInfo.deviceId})`);
            console.log(`📱 New device can now register with client key: ${registrationSession.clientKey}`);
            
            // Clean up
            challenges.delete(challengeId);
            
            res.json({
                success: true,
                message: 'Device registration authorized with new passkey',
                deviceRegistration: {
                    sessionId: challengeData.sessionId,
                    clientKey: registrationSession.clientKey,
                    username: registrationSession.username,
                    authorized: true
                },
                authorizationDevice: {
                    deviceId: authDeviceInfo.deviceId,
                    deviceName: authDeviceInfo.deviceName,
                    credentialId: credentialIdBase64
                }
            });
        } else {
            // Handle existing passkey authorization (fallback)
            return res.status(400).json({ 
                error: 'Assertion-based authorization not implemented in this flow' 
            });
        }
    } catch (error) {
        console.error('Device registration authorization verification error:', error);
        res.status(400).json({ error: 'Device registration authorization verification failed' });
    }
});

// Check device registration status
app.get('/auth/device/status/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    
    const registrationSession = deviceRegistrationSessions.get(sessionId);
    if (!registrationSession) {
        return res.status(404).json({ 
            error: 'Registration session not found or expired' 
        });
    }
    
    res.json({
        sessionId,
        status: registrationSession.status,
        username: registrationSession.username,
        timestamp: registrationSession.timestamp,
        completedAt: registrationSession.completedAt || null,
        clientKey: registrationSession.status === 'completed' ? registrationSession.clientKey : null
    });
});

// New device completes registration with authorized client key
app.post('/auth/device/complete', async (req, res) => {
    try {
        const { sessionId, deviceName } = req.body;
        
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }
        
        const registrationSession = deviceRegistrationSessions.get(sessionId);
        if (!registrationSession || registrationSession.status !== 'completed') {
            return res.status(400).json({ 
                error: 'Registration session not found, expired, or not yet authorized' 
            });
        }
        
        const { username, clientKey } = registrationSession;
        
        // Generate registration options for the new device
        const userIdData = `${username}:${clientKey}`;
        const userId = Buffer.from(userIdData, 'utf8');
        
        const registrationOptions = await fido2.attestationOptions();
        const challengeId = crypto.randomUUID();
        
        challenges.set(challengeId, {
            challenge: registrationOptions.challenge,
            username,
            displayName: username,
            deviceName: deviceName || 'New Device',
            clientKey,
            userId: userId.toString('base64url'),
            userIdData,
            isNewDeviceRegistration: true,
            registrationSessionId: sessionId,
            timestamp: Date.now()
        });
        
        console.log(`📱 New device registration challenge created for ${username}`);
        console.log(`🔑 Using existing client key: ${clientKey}`);
        
        const challengeBase64url = Buffer.from(registrationOptions.challenge).toString('base64url');
        
        res.json({
            challengeId,
            clientKey,
            publicKey: {
                ...registrationOptions,
                challenge: challengeBase64url,
                user: {
                    id: userId.toString('base64url'),
                    name: username,
                    displayName: clientKey
                },
                excludeCredentials: [],
                authenticatorSelection: {
                    userVerification: "required",
                    residentKey: "required"
                },
                timeout: 60000
            }
        });
    } catch (error) {
        console.error('Device registration completion error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// QR Code Cross-Device Authentication Endpoints

// Initiate QR code authentication
app.post('/auth/qr/initiate', async (req, res) => {
    try {
        const { deviceName } = req.body;
        
        // Generate session ID for cross-device authentication
        const sessionId = uuidv4();
        const sessionData = {
            sessionId,
            deviceName: deviceName || 'Unknown Device',
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: Date.now() + 300000, // 5 minutes
            authenticatedUser: null
        };
        
        crossDeviceSessions.set(sessionId, sessionData);
        
        // Generate QR code data
        const qrData = {
            sessionId,
            serverUrl: `http://localhost:${PORT}`,
            action: 'authenticate',
            timestamp: Date.now()
        };
        
        // Generate QR code image
        const qrCodeDataUrl = await QRCode.toDataURL(JSON.stringify(qrData), {
            width: 300,
            margin: 2,
            color: {
                dark: '#000000',
                light: '#FFFFFF'
            }
        });
        
        res.json({
            sessionId,
            qrCodeDataUrl,
            qrData,
            expiresAt: sessionData.expiresAt
        });
    } catch (error) {
        console.error('QR initiation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Check QR code authentication status
app.get('/auth/qr/status/:sessionId', (req, res) => {
    try {
        const { sessionId } = req.params;
        const sessionData = crossDeviceSessions.get(sessionId);
        
        if (!sessionData) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        // Check if session expired
        if (Date.now() > sessionData.expiresAt) {
            crossDeviceSessions.delete(sessionId);
            return res.json({ 
                status: 'expired',
                message: 'Session expired' 
            });
        }
        
        res.json({
            status: sessionData.status,
            authenticatedUser: sessionData.authenticatedUser,
            deviceName: sessionData.deviceName,
            expiresAt: sessionData.expiresAt
        });
    } catch (error) {
        console.error('QR status check error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Complete QR code authentication from mobile device
app.post('/auth/qr/complete', async (req, res) => {
    try {
        const { sessionId, username } = req.body;
        
        if (!sessionId || !username) {
            return res.status(400).json({ 
                error: 'Session ID and username are required' 
            });
        }
        
        // Check if session exists
        const sessionData = crossDeviceSessions.get(sessionId);
        if (!sessionData) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        // Check if session expired
        if (Date.now() > sessionData.expiresAt) {
            crossDeviceSessions.delete(sessionId);
            return res.status(400).json({ error: 'Session expired' });
        }
        
        // Check if user exists
        const user = users.get(username);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        
        // Generate authentication challenge for the mobile device
        const authOptions = await fido2.assertionOptions();
        const challengeId = uuidv4();
        
        challenges.set(challengeId, {
            challenge: authOptions.challenge,
            username,
            sessionId, // Link to cross-device session
            timestamp: Date.now()
        });
        
        // Prepare allowed credentials
        const allowCredentials = user.credentials.map(cred => ({
            id: Buffer.from(cred.credentialId).toString('base64url'),
            type: "public-key",
            transports: ["internal", "hybrid"]
        }));
        
        // Convert challenge to base64url for client
        const challengeBase64url = Buffer.from(authOptions.challenge).toString('base64url');
        
        res.json({
            challengeId,
            publicKey: {
                ...authOptions,
                challenge: challengeBase64url,
                allowCredentials
            }
        });
    } catch (error) {
        console.error('QR complete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify QR code authentication
app.post('/auth/qr/verify', async (req, res) => {
    try {
        const { challengeId, credential } = req.body;
        
        if (!challengeId || !credential) {
            return res.status(400).json({ 
                error: 'Challenge ID and credential are required' 
            });
        }
        
        // Get challenge data
        const challengeData = challenges.get(challengeId);
        if (!challengeData) {
            return res.status(400).json({ 
                error: 'Invalid or expired challenge' 
            });
        }
        
        // Get user data
        const user = users.get(challengeData.username);
        if (!user) {
            return res.status(400).json({ 
                error: 'User not found' 
            });
        }
        
        // Find matching credential
        const userCredential = user.credentials.find(cred => 
            cred.credentialId.equals(Buffer.from(credential.id, 'base64url'))
        );
        
        if (!userCredential) {
            return res.status(400).json({ 
                error: 'Credential not found' 
            });
        }
        
        // Convert credential data from base64url strings to ArrayBuffers
        const credentialForVerification = {
            id: Buffer.from(credential.id, 'base64url').buffer,
            rawId: Buffer.from(credential.rawId, 'base64url').buffer,
            response: {
                clientDataJSON: Buffer.from(credential.response.clientDataJSON, 'base64url').buffer,
                authenticatorData: Buffer.from(credential.response.authenticatorData, 'base64url').buffer,
                signature: Buffer.from(credential.response.signature, 'base64url').buffer,
                userHandle: credential.response.userHandle ? Buffer.from(credential.response.userHandle, 'base64url').buffer : null
            },
            type: credential.type
        };
        
        // Verify authentication
        const assertionExpectations = {
            challenge: challengeData.challenge,
            origin: `http://localhost:${PORT}`,
            factor: "either",
            publicKey: userCredential.publicKey,
            prevCounter: userCredential.counter,
            userHandle: user.id
        };
        
        const authResult = await fido2.assertionResult(credentialForVerification, assertionExpectations);
        
        // Update counter
        userCredential.counter = authResult.authnrData.get("counter");
        
        // Update cross-device session
        if (challengeData.sessionId) {
            const sessionData = crossDeviceSessions.get(challengeData.sessionId);
            if (sessionData) {
                sessionData.status = 'authenticated';
                sessionData.authenticatedUser = {
                    id: user.id,
                    username: user.username,
                    displayName: user.displayName,
                    authenticatedAt: new Date().toISOString()
                };
            }
        }
        
        // Clean up challenge
        challenges.delete(challengeId);
        
        res.json({
            success: true,
            message: 'Cross-device authentication successful',
            user: {
                id: user.id,
                username: user.username,
                displayName: user.displayName
            }
        });
    } catch (error) {
        console.error('QR verification error:', error);
        res.status(400).json({ 
            error: 'Authentication verification failed' 
        });
    }
});

// Admin endpoints for debugging
app.get('/admin/users', (req, res) => {
    // Get unique users (in case of multiple credentials per user)
    const uniqueUsers = new Map();
    for (const [credentialId, user] of users.entries()) {
        if (!uniqueUsers.has(user.username)) {
            uniqueUsers.set(user.username, {
                credentialId: credentialId.substring(0, 16) + '...', // Show first 16 chars
                username: user.username,
                displayName: user.displayName,
                authType: 'password+passkey+client-key',
                hasPassword: !!user.hashedPassword,
                hasClientKey: !!user.clientKey,
                credentialCount: user.credentials.length,
                createdAt: user.createdAt,
                lastRegistered: user.credentials[user.credentials.length - 1]?.createdAt
            });
        }
    }
    
    const userList = Array.from(uniqueUsers.values());
    
    res.json({
        users: userList,
        totalUsers: users.size
    });
});

app.delete('/admin/users/:credentialId', (req, res) => {
    const { credentialId } = req.params;
    
    if (users.has(credentialId)) {
        const user = users.get(credentialId);
        users.delete(credentialId);
        res.json({ success: true, message: `User ${user.username} deleted` });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Passkey + Client Key Server running on port ${PORT}`);
    console.log(`🌐 Visit http://localhost:${PORT} to see available endpoints`);
    console.log(`📋 Health check: http://localhost:${PORT}/health`);
    console.log(`👥 Admin panel: http://localhost:${PORT}/admin/users`);
}); 