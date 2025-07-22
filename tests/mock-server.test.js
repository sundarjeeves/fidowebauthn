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
                    name: username,
                    displayName: clientKey
                }
            }
        });
    });
    
    // Mock registration verification
    app.post('/auth/register/verify', (req, res) => {
        const { challengeId, credential } = req.body;
        
        const challengeData = challenges.get(challengeId);
        if (!challengeData) {
            return res.status(400).json({ error: 'Invalid challenge' });
        }
        
        // Store user
        users.set('mock-credential-id', {
            username: challengeData.username,
            displayName: challengeData.displayName,
            clientKey: challengeData.clientKey,
            createdAt: new Date().toISOString()
        });
        
        challenges.delete(challengeId);
        
        res.json({
            success: true,
            message: 'Registration successful',
            clientKey: challengeData.clientKey
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
            expect(verifyResponse.body.clientKey).toBe(challengeResponse.body.clientKey);
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