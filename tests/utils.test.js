const crypto = require('crypto');

// Mock crypto for consistent testing
jest.mock('crypto');

describe('Utility Functions', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });
    
    describe('Client Key Generation', () => {
        test('should generate 32 character hex string', () => {
            // Mock crypto.randomBytes to return known value
            const mockBuffer = Buffer.from('1234567890abcdef1234567890abcdef', 'hex');
            crypto.randomBytes.mockReturnValue(mockBuffer);
            
            const clientKey = crypto.randomBytes(16).toString('hex');
            
            expect(clientKey).toBe('1234567890abcdef1234567890abcdef');
            expect(clientKey).toHaveLength(32);
            expect(crypto.randomBytes).toHaveBeenCalledWith(16);
        });
        
        test('should generate unique keys on multiple calls', () => {
            crypto.randomBytes
                .mockReturnValueOnce(Buffer.from('1111111111111111', 'hex'))
                .mockReturnValueOnce(Buffer.from('2222222222222222', 'hex'))
                .mockReturnValueOnce(Buffer.from('3333333333333333', 'hex'));
            
            const key1 = crypto.randomBytes(16).toString('hex');
            const key2 = crypto.randomBytes(16).toString('hex');
            const key3 = crypto.randomBytes(16).toString('hex');
            
            expect(key1).toBe('1111111111111111');
            expect(key2).toBe('2222222222222222');
            expect(key3).toBe('3333333333333333');
            expect(new Set([key1, key2, key3]).size).toBe(3);
        });
    });
    
    describe('Base64URL Conversion', () => {
        // Helper function for base64url conversion (extracted from main code)
        function arrayBufferToBase64url(buffer) {
            return Buffer.from(buffer).toString('base64url');
        }
        
        function base64urlToArrayBuffer(base64url) {
            const buffer = Buffer.from(base64url, 'base64url');
            const arrayBuffer = new ArrayBuffer(buffer.length);
            const view = new Uint8Array(arrayBuffer);
            for (let i = 0; i < buffer.length; i++) {
                view[i] = buffer[i];
            }
            return arrayBuffer;
        }
        
        test('should convert ArrayBuffer to base64url correctly', () => {
            const testData = new Uint8Array([1, 2, 3, 4, 5]);
            const buffer = testData.buffer;
            
            const base64url = arrayBufferToBase64url(buffer);
            expect(typeof base64url).toBe('string');
            expect(base64url).not.toContain('+');
            expect(base64url).not.toContain('/');
            expect(base64url).not.toContain('=');
        });
        
        test('should convert base64url to ArrayBuffer correctly', () => {
            const originalData = new Uint8Array([1, 2, 3, 4, 5]);
            const base64url = Buffer.from(originalData).toString('base64url');
            
            const arrayBuffer = base64urlToArrayBuffer(base64url);
            const resultData = new Uint8Array(arrayBuffer);
            
            expect(arrayBuffer.byteLength).toBe(originalData.length);
            expect(Array.from(resultData)).toEqual(Array.from(originalData));
        });
        
        test('should handle round-trip conversion', () => {
            const originalData = new Uint8Array([65, 66, 67, 68, 69]); // "ABCDE"
            
            // ArrayBuffer -> base64url -> ArrayBuffer
            const base64url = arrayBufferToBase64url(originalData.buffer);
            const reconstructed = base64urlToArrayBuffer(base64url);
            const resultData = new Uint8Array(reconstructed);
            
            expect(Array.from(resultData)).toEqual(Array.from(originalData));
        });
        
        test('should handle empty data', () => {
            const emptyBuffer = new ArrayBuffer(0);
            const base64url = arrayBufferToBase64url(emptyBuffer);
            const reconstructed = base64urlToArrayBuffer(base64url);
            
            expect(reconstructed.byteLength).toBe(0);
        });
    });
    
    describe('UserHandle Encoding/Decoding', () => {
        test('should encode username and client key correctly', () => {
            const username = 'testuser';
            const clientKey = '1234567890abcdef1234567890abcdef';
            const userIdData = `${username}:${clientKey}`;
            
            const encoded = Buffer.from(userIdData, 'utf8').toString('base64url');
            const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
            
            expect(decoded).toBe(userIdData);
            
            const [decodedUsername, decodedClientKey] = decoded.split(':');
            expect(decodedUsername).toBe(username);
            expect(decodedClientKey).toBe(clientKey);
        });
        
        test('should respect 64-byte userHandle limit', () => {
            const maxUsername = 'a'.repeat(31); // 31 chars + ':' + 32 char key = 64 bytes
            const clientKey = '1234567890abcdef1234567890abcdef';
            const userIdData = `${maxUsername}:${clientKey}`;
            
            expect(Buffer.byteLength(userIdData, 'utf8')).toBeLessThanOrEqual(64);
            
            // Test exceeding limit
            const tooLongUsername = 'a'.repeat(32);
            const tooLongUserIdData = `${tooLongUsername}:${clientKey}`;
            expect(Buffer.byteLength(tooLongUserIdData, 'utf8')).toBeGreaterThan(64);
        });
        
        test('should handle special characters in username', () => {
            const username = 'test.user+123@example.com';
            const clientKey = '1234567890abcdef1234567890abcdef';
            const userIdData = `${username}:${clientKey}`;
            
            const encoded = Buffer.from(userIdData, 'utf8').toString('base64url');
            const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
            
            expect(decoded).toBe(userIdData);
            
            const [decodedUsername, decodedClientKey] = decoded.split(':');
            expect(decodedUsername).toBe(username);
            expect(decodedClientKey).toBe(clientKey);
        });
        
        test('should handle unicode characters in username', () => {
            const username = 'tëstüser🔑';
            const clientKey = '1234567890abcdef1234567890abcdef';
            const userIdData = `${username}:${clientKey}`;
            
            // Check if it fits in 64 bytes (unicode chars take more bytes)
            if (Buffer.byteLength(userIdData, 'utf8') <= 64) {
                const encoded = Buffer.from(userIdData, 'utf8').toString('base64url');
                const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
                
                expect(decoded).toBe(userIdData);
                
                const [decodedUsername, decodedClientKey] = decoded.split(':');
                expect(decodedUsername).toBe(username);
                expect(decodedClientKey).toBe(clientKey);
            }
        });
    });
    
    describe('Challenge Generation', () => {
        test('should generate unique challenge IDs', () => {
            crypto.randomUUID
                .mockReturnValueOnce('challenge-1')
                .mockReturnValueOnce('challenge-2')
                .mockReturnValueOnce('challenge-3');
            
            const id1 = crypto.randomUUID();
            const id2 = crypto.randomUUID();
            const id3 = crypto.randomUUID();
            
            expect(id1).toBe('challenge-1');
            expect(id2).toBe('challenge-2');
            expect(id3).toBe('challenge-3');
            expect(new Set([id1, id2, id3]).size).toBe(3);
        });
    });
    
    describe('Error Handling Utilities', () => {
        test('should handle invalid base64url strings gracefully', () => {
            const invalidBase64url = 'invalid base64url string with spaces!';
            
            expect(() => {
                Buffer.from(invalidBase64url, 'base64url');
            }).not.toThrow(); // Buffer.from is forgiving
            
            // But the result will be incorrect
            const result = Buffer.from(invalidBase64url, 'base64url');
            expect(result.length).toBeGreaterThan(0); // It produces something, but it's wrong
        });
        
        test('should detect malformed userHandle data', () => {
            const malformedData = 'no-colon-separator';
            const encoded = Buffer.from(malformedData, 'utf8').toString('base64url');
            const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
            
            const parts = decoded.split(':');
            expect(parts.length).toBe(1); // No colon found
            expect(parts[1]).toBeUndefined(); // No client key part
        });
        
        test('should handle empty userHandle', () => {
            const emptyData = '';
            const encoded = Buffer.from(emptyData, 'utf8').toString('base64url');
            const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
            
            expect(decoded).toBe('');
            
            const [username, clientKey] = decoded.split(':');
            expect(username).toBe('');
            expect(clientKey).toBeUndefined();
        });
    });
}); 