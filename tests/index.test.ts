import { generate } from '../index';

describe('generate', () => {
    it('should generate OTP with default options', () => {
        const key = 'JBSWY3DPEHPK3PXP';
        const timestamp = 1465324707000;
        const otp = generate(key, { timestamp }).otp;
        expect(otp).toBe(461529);
    });

    it('should generate OTP with custom options', () => {
        const key = 'JBSWY3DPEHPK3PXP';
        const timestamp = 1465324707000;
        const algorithm = 'SHA-256';
        const digits = 8;
        const otp = generate(key, { timestamp, algorithm, digits }).otp;
        expect(otp).toBe(61461529);
    });

    it('should generate OTP with current timestamp', () => {
        const key = 'JBSWY3DPEHPK3PXP';
        const otp = generate(key).otp;
        expect(typeof otp).toBe('number');
    });

    it('should generate OTP with expires timestamp', () => {
        const key = 'JBSWY3DPEHPK3PXP';
        const { expires } = generate(key);
        expect(typeof expires).toBe('number');
    });
});