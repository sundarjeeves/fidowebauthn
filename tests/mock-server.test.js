const request = require('supertest');
const express = require('express');

// Create a minimal mock server for testing core logic without external dependencies
function createMockServer() {
    const app = express();
    app.use(express.json());
    
    // In-memory storage
    const users = new Map();
    const challenges = new Map();
    
    // Mock registration challenge
    app.post('/auth/register/challenge', (req, res) => {
        const { username, displayName, password } = req.body;
        
        if (!username || !displayName || !password) {
            return res.status(400).json({ 
                error: 'Username, displayName, and password are required' 
            });
        }
        
        // Check if user exists
        const existingUser = Array.from(users.values()).find(u => u.username === username);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Mock successful challenge
        const challengeId = 'mock-challenge-id';
        const clientKey = 'mock-client-key-1234567890abcdef';
        
        challenges.set(challengeId, {
            username,
            displayName,
            clientKey,
            timestamp: Date.now()
        });
        
        res.json({
            challengeId,
            clientKey,
            publicKey: {
                challenge: 'mock-challenge',
                user: {
                    id: `${username}:${clientKey}`,
                    name: `${username} [Key: ${clientKey.substring(0, 8)}...]`, // Include partial key for Keeper visibility
                    displayName: clientKey
                }
            }
        });
    });
    
    // Mock test client key extraction endpoint
    app.get('/auth/test-client-key/:username', (req, res) => {
        const { username } = req.params;
        
        const user = Array.from(users.values()).find(u => u.username === username);
        
        if (!user) {
            return res.status(404).json({
                error: `User "${username}" not found. Available users: ${Array.from(users.values()).map(u => u.username).join(', ')}`
            });
        }
        
        // Extract client key from userIdData (format: "username:clientKey")
        const [extractedUsername, extractedClientKey] = user.userIdData.split(':');
        
        res.json({
            success: true,
            username: extractedUsername,
            clientKey: extractedClientKey,
            userId: user.userIdData,
            storedClientKey: user.clientKey,
            match: extractedClientKey === user.clientKey,
            message: 'Client key successfully extracted from passkey userHandle'
        });
    });
    
    // Mock registration verification
    app.post('/auth/register/verify', (req, res) => {
        const { challengeId, credential } = req.body;
        
        const challenge = challenges.get(challengeId);
        if (!challenge) {
            return res.status(400).json({ error: 'Invalid challenge' });
        }
        
        // Store user with embedded client key
        const userId = `${challenge.username}:${challenge.clientKey}`;
        users.set(credential.id, {
            credentialId: credential.id,
            username: challenge.username,
            displayName: challenge.displayName,
            clientKey: challenge.clientKey,
            userIdData: userId,
            hashedPassword: 'mock-hashed-password',
            credentials: [{
                credentialId: credential.id,
                credentialIdBase64: credential.id,
                publicKey: 'mock-public-key',
                counter: 0,
                createdAt: new Date().toISOString()
            }],
            createdAt: new Date().toISOString()
        });
        
        challenges.delete(challengeId);
        
        res.json({
            success: true,
            userId: userId,
            message: 'Registration successful'
        });
    });
    
    // Mock login challenge
    app.post('/auth/login/challenge', (req, res) => {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }
        
        const user = Array.from(users.values()).find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        
        const challengeId = 'mock-auth-challenge-id';
        challenges.set(challengeId, { username, timestamp: Date.now() });
        
        res.json({
            challengeId,
            publicKey: {
                challenge: 'mock-auth-challenge',
                allowCredentials: [{ id: 'mock-credential-id', type: 'public-key' }]
            }
        });
    });
    
    // Mock login verification
    app.post('/auth/login/verify', (req, res) => {
        const { challengeId, username, password, credential } = req.body;
        
        if (!challengeId || !username || !password || !credential) {
            return res.status(400).json({ 
                error: 'Challenge ID, username, password, and credential are required' 
            });
        }
        
        const challengeData = challenges.get(challengeId);
        if (!challengeData || challengeData.username !== username) {
            return res.status(400).json({ error: 'Invalid challenge' });
        }
        
        const user = Array.from(users.values()).find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        
        // Mock password verification (always pass for test)
        if (password !== 'testpassword123' && password !== 'correctpassword') {
            return res.status(400).json({ error: 'Invalid password' });
        }
        
        challenges.delete(challengeId);
        
        res.json({
            success: true,
            message: 'Authentication successful',
            user: {
                username: user.username,
                displayName: user.displayName,
                clientKey: user.clientKey
            }
        });
    });
    
    // Admin endpoints
    app.get('/admin/users', (req, res) => {
        const userList = Array.from(users.values()).map(user => ({
            username: user.username,
            displayName: user.displayName,
            hasClientKey: !!user.clientKey,
            createdAt: user.createdAt
        }));
        
        res.json({
            users: userList,
            totalUsers: users.size
        });
    });
    
    return app;
}

describe('Mock Server Tests', () => {
    let app;
    
    beforeEach(() => {
        app = createMockServer();
    });
    
    describe('Registration Flow', () => {
        test('should register a user successfully', async () => {
            // Test challenge
            const challengeResponse = await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Test User',
                    password: 'testpassword123'
                })
                .expect(200);
            
            expect(challengeResponse.body).toHaveProperty('challengeId');
            expect(challengeResponse.body).toHaveProperty('clientKey');
            expect(challengeResponse.body.publicKey.user.displayName).toBe(challengeResponse.body.clientKey);
            
            // Test verification
            const verifyResponse = await request(app)
                .post('/auth/register/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    credential: { id: 'mock-cred', type: 'public-key' }
                })
                .expect(200);
            
            expect(verifyResponse.body.success).toBe(true);
            expect(verifyResponse.body.userId).toContain(challengeResponse.body.clientKey);
        });
        
        test('should reject registration with missing fields', async () => {
            await request(app)
                .post('/auth/register/challenge')
                .send({ username: 'testuser' })
                .expect(400);
        });
        
                 test('should reject duplicate usernames', async () => {
            // First registration - complete the full flow
            const challengeResponse = await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Test User',
                    password: 'testpassword123'
                })
                .expect(200);
            
            // Complete the registration
            await request(app)
                .post('/auth/register/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    credential: { id: 'mock-cred', type: 'public-key' }
                })
                .expect(200);
            
            // Now try duplicate registration
            await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Another User',
                    password: 'anotherpassword'
                })
                .expect(400);
        });
    });
    
    describe('Authentication Flow', () => {
        beforeEach(async () => {
            // Register a test user
            const challengeResponse = await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Test User',
                    password: 'testpassword123'
                });
            
            await request(app)
                .post('/auth/register/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    credential: { id: 'mock-cred', type: 'public-key' }
                });
        });
        
        test('should authenticate successfully', async () => {
            // Test challenge
            const challengeResponse = await request(app)
                .post('/auth/login/challenge')
                .send({ username: 'testuser' })
                .expect(200);
            
            expect(challengeResponse.body).toHaveProperty('challengeId');
            
            // Test verification
            const verifyResponse = await request(app)
                .post('/auth/login/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    username: 'testuser',
                    password: 'testpassword123',
                    credential: { id: 'mock-cred', type: 'public-key' }
                })
                .expect(200);
            
            expect(verifyResponse.body.success).toBe(true);
            expect(verifyResponse.body.user.username).toBe('testuser');
        });
        
        test('should reject wrong password', async () => {
            const challengeResponse = await request(app)
                .post('/auth/login/challenge')
                .send({ username: 'testuser' })
                .expect(200);
            
            await request(app)
                .post('/auth/login/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    username: 'testuser',
                    password: 'wrongpassword',
                    credential: { id: 'mock-cred', type: 'public-key' }
                })
                .expect(400);
        });
        
        test('should reject non-existent user', async () => {
            await request(app)
                .post('/auth/login/challenge')
                .send({ username: 'nonexistent' })
                .expect(400);
        });
        
        test('should require all parameters for authentication', async () => {
            const challengeResponse = await request(app)
                .post('/auth/login/challenge')
                .send({ username: 'testuser' })
                .expect(200);
            
            // Missing parameters
            await request(app)
                .post('/auth/login/verify')
                .send({
                    challengeId: challengeResponse.body.challengeId,
                    username: 'testuser'
                    // Missing password and credential
                })
                .expect(400);
        });
    });
    
    describe('Admin Endpoints', () => {
        test('should return user list', async () => {
            const response = await request(app)
                .get('/admin/users')
                .expect(200);
            
            expect(response.body).toHaveProperty('users');
            expect(response.body).toHaveProperty('totalUsers');
            expect(Array.isArray(response.body.users)).toBe(true);
        });
    });
    
    describe('Client Key Functionality', () => {
        test('should embed client key in user data correctly', async () => {
            const challengeResponse = await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Test User',
                    password: 'testpassword123'
                })
                .expect(200);
            
            const userIdData = challengeResponse.body.publicKey.user.id;
            expect(userIdData).toContain('testuser:');
            expect(userIdData).toContain(challengeResponse.body.clientKey);
            
            // Verify displayName contains client key
            expect(challengeResponse.body.publicKey.user.displayName).toBe(challengeResponse.body.clientKey);
        });
        
        test('should maintain client key through auth flow', async () => {
            // Register
            const regResponse = await request(app)
                .post('/auth/register/challenge')
                .send({
                    username: 'testuser',
                    displayName: 'Test User',
                    password: 'testpassword123'
                });
            
            await request(app)
                .post('/auth/register/verify')
                .send({
                    challengeId: regResponse.body.challengeId,
                    credential: { id: 'mock-cred', type: 'public-key' }
                });
            
            // Authenticate
            const authChallengeResponse = await request(app)
                .post('/auth/login/challenge')
                .send({ username: 'testuser' });
            
            const authResponse = await request(app)
                .post('/auth/login/verify')
                .send({
                    challengeId: authChallengeResponse.body.challengeId,
                    username: 'testuser',
                    password: 'testpassword123',
                    credential: { id: 'mock-cred', type: 'public-key' }
                });
            
            // Client key should be preserved
            expect(authResponse.body.user.clientKey).toBe(regResponse.body.clientKey);
        });
    });
});

describe('Client Key Extraction Debug Endpoint', () => {
    let server;
    
    beforeEach(() => {
        server = createMockServer();
    });
    
    test('should extract client key from registered user', async () => {
        // First register a user
        const registerResponse = await request(server)
            .post('/auth/register/challenge')
            .send({
                username: 'testuser',
                displayName: 'Test User',
                password: 'password123'
            });
        
        expect(registerResponse.status).toBe(200);
        const { challengeId, clientKey } = registerResponse.body;
        
        // Verify registration
        await request(server)
            .post('/auth/register/verify')
            .send({
                challengeId,
                credential: {
                    id: 'mock-credential-id',
                    rawId: 'mock-raw-id',
                    response: {
                        clientDataJSON: 'mock-client-data',
                        attestationObject: 'mock-attestation'
                    }
                }
            });
        
        // Test client key extraction
        const extractResponse = await request(server)
            .get('/auth/test-client-key/testuser');
        
        expect(extractResponse.status).toBe(200);
        expect(extractResponse.body.success).toBe(true);
        expect(extractResponse.body.username).toBe('testuser');
        expect(extractResponse.body.clientKey).toBe(clientKey);
        expect(extractResponse.body.match).toBe(true);
        expect(extractResponse.body.message).toContain('Client key successfully extracted');
    });
    
    test('should return 404 for non-existent user', async () => {
        const response = await request(server)
            .get('/auth/test-client-key/nonexistent');
        
        expect(response.status).toBe(404);
        expect(response.body.error).toContain('User "nonexistent" not found');
    });
});

describe('Keeper Secret Manager Compatibility', () => {
    let server;
    
    beforeEach(() => {
        server = createMockServer();
    });
    
    test('should include partial client key in passkey name for Keeper visibility', async () => {
        const response = await request(server)
            .post('/auth/register/challenge')
            .send({
                username: 'keeperuser',
                displayName: 'Keeper User',
                password: 'password123'
            });
        
        expect(response.status).toBe(200);
        expect(response.body.clientKey).toBeDefined();
        
        const { clientKey } = response.body;
        const expectedName = `keeperuser [Key: ${clientKey.substring(0, 8)}...]`;
        
        expect(response.body.publicKey.user.name).toBe(expectedName);
        expect(response.body.publicKey.user.displayName).toBe(clientKey);
    });
    
    test('should store full client key in displayName and partial in name', async () => {
        const response = await request(server)
            .post('/auth/register/challenge')
            .send({
                username: 'dualstoreuser',
                displayName: 'Dual Store User', 
                password: 'password123'
            });
        
        expect(response.status).toBe(200);
        
        const { publicKey, clientKey } = response.body;
        
        // Full client key in displayName (for extraction)
        expect(publicKey.user.displayName).toBe(clientKey);
        
        // Partial client key in name (for Keeper visibility)
        expect(publicKey.user.name).toContain('[Key:');
        expect(publicKey.user.name).toContain(clientKey.substring(0, 8));
        expect(publicKey.user.name).toContain('dualstoreuser');
    });
}); 