const request = require('supertest');
const { spawn } = require('child_process');
const path = require('path');

describe('Integration Tests', () => {
    let serverProcess;
    let baseUrl = 'http://localhost:3001'; // Use different port to avoid conflicts
    
    beforeAll((done) => {
        // Start the actual server on a test port
        const serverPath = path.join(__dirname, '..', 'index.js');
        serverProcess = spawn('node', [serverPath], {
            env: { ...process.env, PORT: '3001' },
            stdio: 'pipe'
        });
        
        // Wait for server to start
        setTimeout(() => {
            done();
        }, 2000);
    });
    
    afterAll((done) => {
        if (serverProcess) {
            serverProcess.kill('SIGTERM');
            setTimeout(done, 1000);
        } else {
            done();
        }
    });
    
    describe('Server Health', () => {
        test('should respond to health check', async () => {
            const response = await request(baseUrl)
                .get('/health')
                .expect(200);
                
            expect(response.body.status).toBe('OK');
        });
        
        test('should serve the main page', async () => {
            const response = await request(baseUrl)
                .get('/')
                .expect(200);
                
            expect(response.text).toContain('Passkey + Client Key Authentication Demo');
        });
    });
    
    describe('Admin Endpoints', () => {
        test('should return empty user list initially', async () => {
            const response = await request(baseUrl)
                .get('/admin/users')
                .expect(200);
                
            expect(response.body.users).toEqual([]);
            expect(response.body.totalUsers).toBe(0);
        });
    });
    
    describe('Authentication Endpoints', () => {
        test('should reject registration without required fields', async () => {
            await request(baseUrl)
                .post('/auth/register/challenge')
                .send({})
                .expect(400);
        });
        
        test('should reject login challenge without username', async () => {
            await request(baseUrl)
                .post('/auth/login/challenge')
                .send({})
                .expect(400);
        });
        
        test('should reject login for non-existent user', async () => {
            await request(baseUrl)
                .post('/auth/login/challenge')
                .send({ username: 'nonexistent' })
                .expect(400);
        });
    });
    
    describe('QR Code Authentication', () => {
        test('should initiate QR authentication with device name', async () => {
            const response = await request(baseUrl)
                .post('/auth/qr/initiate')
                .send({ deviceName: 'Test Device' })
                .expect(200);
                
            expect(response.body).toHaveProperty('sessionId');
            expect(response.body).toHaveProperty('qrCodeDataUrl');
            expect(response.body).toHaveProperty('qrData');
        });
        
        test('should handle QR authentication without device name', async () => {
            const response = await request(baseUrl)
                .post('/auth/qr/initiate')
                .send({})
                .expect(200);
                
            // Should still work but use default device name
            expect(response.body).toHaveProperty('sessionId');
        });
    });
}); 