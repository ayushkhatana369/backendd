import express from "express";
import cors from "cors";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";

const app = express();
app.use(cors());
app.use(express.json());

/**
 * API: Generate a new keypair
 * Returns: { publicKey (base58), secretKey (hex) }
 */
app.get("/generate-keypair", (req, res) => {
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toBase58();
  const secretKeyHex = Buffer.from(keypair.secretKey).toString("hex");

  res.json({ publicKey, secretKey: secretKeyHex });
});

/**
 * API: Sign a message
 * Input: { message, secretKey (hex) }
 * Returns: { signature (hex) }
 */
app.post("/sign-message", (req, res) => {
  const { message, secretKey } = req.body;

  if (!message || !secretKey) {
    return res
      .status(400)
      .json({ error: "Message and secretKey (hex) are required" });
  }

  const secretKeyUint8 = new Uint8Array(Buffer.from(secretKey, "hex"));
  const encodedMessage = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(encodedMessage, secretKeyUint8);

  res.json({ signature: Buffer.from(signature).toString("hex") });
});

/**
 * API: Verify a signed message
 * Input: { message, signature (hex), publicKey (base58) }
 * Returns: { verified: true/false }
 */
app.post("/verify-message", (req, res) => {
  const { message, signature, publicKey } = req.body;

  if (!message || !signature || !publicKey) {
    return res
      .status(400)
      .json({ error: "Message, signature, and publicKey are required" });
  }

  try {
    const encodedMessage = new TextEncoder().encode(message);
    const signatureUint8 = new Uint8Array(Buffer.from(signature, "hex"));
    const publicKeyUint8 = bs58.decode(publicKey); // decode base58 Solana public key

    const verified = nacl.sign.detached.verify(
      encodedMessage,
      signatureUint8,
      publicKeyUint8
    );

    res.json({ verified });
  } catch (err) {
    res.status(400).json({ error: "Invalid public key or signature format" });
  }
});

// ✅ Use the port Render provides, default to 5000 locally
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
