import crypto from "crypto";

/**
 * Options for initializing the Cryptographic class.
 */
interface CryptographicOptions {
  secretKey: string;
  salt: string;
}

class Cryptographic {
  /** The secret key used for cryptographic operations. */
  readonly secretKey: string;
  /** The salt value used for cryptographic operations. */
  readonly salt: string;

  /**
   * Initializes a new Cryptographic instance.
   *
   * @param options - The options for initializing the Cryptographic instance.
   */
  constructor({ secretKey, salt }: CryptographicOptions) {
    if (!secretKey || !salt) {
      throw new Error("Secret key and salt must be provided.");
    }
    this.secretKey = secretKey;
    this.salt = salt;
  }

  /**
   * Generates a derived key using PBKDF2.
   *
   * @returns A Promise that resolves to the derived key as a Buffer.
   */
  async generateDerivedKey(): Promise<Buffer> {
    const iterations = 10000;
    const keyLength = 32;
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        Buffer.from(this.secretKey),
        Buffer.from(this.salt),
        iterations,
        keyLength,
        "sha256",
        (err, derivedKey) => {
          if (err) {
            reject(err);
          } else {
            resolve(derivedKey);
          }
        }
      );
    });
  }

  /**
   * Encrypts data using AES-256-CTR encryption.
   *
   * @param data - The data to be encrypted.
   * @param expirationTime - Optional expiration time for the data.
   * @returns The encrypted data as a string.
   */
  async encrypt(data: any, expirationTime?: number) {
    const derivedKey = await this.generateDerivedKey();
    const iv = crypto.randomBytes(16);
    const algorithm = "aes-256-ctr";
    const cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
    const dataToEncrypt = expirationTime
      ? { value: data, expirationTime }
      : { value: data };
    const jsonData = JSON.stringify(dataToEncrypt);
    const encrypted = Buffer.concat([cipher.update(jsonData), cipher.final()]);
    const ivHex = iv.toString("hex");
    const encryptedHex = encrypted.toString("hex");
    return `${ivHex}:${encryptedHex}`;
  }

  /**
   * Decrypts encrypted text using AES-256-CTR decryption.
   *
   * @param encryptedText - The text to be decrypted.
   * @returns The decrypted data as a string.
   */
  async decrypt(encryptedText: string) {
    const derivedKey = await this.generateDerivedKey();
    const [ivHex, encryptedHex] = encryptedText.split(":");
    if (!ivHex || !encryptedHex) {
      throw new Error("Invalid encrypted text format");
    }
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-ctr", derivedKey, iv);
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, "hex")),
      decipher.final(),
    ]);
    const decryptedData = JSON.parse(decrypted.toString());
    const { value, expirationTime } = decryptedData;
    if (expirationTime && Date.now() > expirationTime) {
      throw new Error("It has expired");
    }
    return value;
  }
}

export default Cryptographic;
