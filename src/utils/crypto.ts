import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

/**
 * Derives a consistent 32-byte (256-bit) buffer key from the environment variable.
 */
function getKey(): Buffer {
  const rawKey = process.env.ENCRYPTION_KEY;
  if (!rawKey) {
    throw new Error('Security Error: ENCRYPTION_KEY environment variable is missing.');
  }
  if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
    return Buffer.from(rawKey, 'hex');
  }
  return crypto.createHash('sha256').update(rawKey).digest();
}

/**
 * Checks if a string matches the encrypted payload format `iv:authTag:ciphertext`.
 */
export function isEncrypted(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const parts = val.split(':');
  if (parts.length !== 3) return false;
  const [ivHex, tagHex, encHex] = parts;
  return (
    ivHex.length === IV_LENGTH * 2 &&
    tagHex.length === TAG_LENGTH * 2 &&
    /^[0-9a-fA-F]+$/.test(ivHex) &&
    /^[0-9a-fA-F]+$/.test(tagHex) &&
    /^[0-9a-fA-F]+$/.test(encHex)
  );
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns payload in the format: `${ivHex}:${authTagHex}:${ciphertextHex}`
 */
export function encrypt(text: string | null | undefined): string | null | undefined {
  if (!text || typeof text !== 'string') return text;
  if (isEncrypted(text)) return text; // Prevent double encryption

  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypts an AES-256-GCM encrypted payload back to plaintext.
 * Returns the original text if decryption succeeds, or the payload unchanged if not encrypted or corrupted.
 */
export function decrypt(payload: string | null | undefined): string | null | undefined {
  if (!payload || typeof payload !== 'string') return payload;
  if (!isEncrypted(payload)) return payload;

  try {
    const [ivHex, tagHex, encHex] = payload.split(':');
    const key = getKey();
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(tagHex, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    // Return original payload if decryption or tag verification fails
    return payload;
  }
}

