package org.example.sm2;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.util.Optional;

public class SM2JCECipher {

    private final static Provider PROVIDER = new BouncyCastleProvider();

    /**
     * SM2 算法加密数据
     *
     * @param data      待加密的数据
     * @param publicKey 加密数据的公钥，格式必须是 0x04||X||Y
     * @return 加密得到的密文
     * @throws GeneralSecurityException 密钥非法
     */
    public static byte[] encrypt(byte[] data, byte[] publicKey) throws GeneralSecurityException {
        X9ECParameters sm2p256v1 = Optional.ofNullable(ECNamedCurveTable.getByName("sm2p256v1"))
                .orElseThrow(() -> new IllegalArgumentException("未找到 SM2 曲线"));
        ECPoint Q = sm2p256v1.getCurve().decodePoint(publicKey);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(Q, EC5Util.convertSpec(EC5Util.convertToSpec(sm2p256v1)));
        PublicKey key = KeyFactory.getInstance("EC", PROVIDER).generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * SM2 算法解密数据
     *
     * @param ciphertext 数据密文
     * @param privateKey 解密数据的私钥
     * @return 数据明文
     * @throws GeneralSecurityException 密钥或密文非法
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] privateKey) throws GeneralSecurityException {
        X9ECParameters sm2p256v1 = Optional.ofNullable(ECNamedCurveTable.getByName("sm2p256v1"))
                .orElseThrow(() -> new IllegalArgumentException("未找到 SM2 曲线"));
        ECParameterSpec parameterSpec = EC5Util.convertSpec(EC5Util.convertToSpec(sm2p256v1));
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, privateKey), parameterSpec);
        PrivateKey key = KeyFactory.getInstance("EC", PROVIDER).generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        byte[] data = "test data".getBytes();
        String publicKey = "04aa0a857024856bffd15fb0bbb58107059c2f0947b6859f42502dae9006481838c52ac25c044f3059a26bcba063ea4f1a904fdf7c22e9bbbea51f3d89d0f9c9fd";
        String privateKey = "79544a0b4116272629715026bcae2bcc5795c998259fb2659182ee6b4a0e8344";
        byte[] ciphertext = encrypt(data, Hex.decode(publicKey));
        System.out.println("密文：" + Hex.toHexString(ciphertext));
        byte[] plaintext = decrypt(ciphertext, Hex.decode(privateKey));
        System.out.println("明文：" + new String(plaintext));
    }

}
