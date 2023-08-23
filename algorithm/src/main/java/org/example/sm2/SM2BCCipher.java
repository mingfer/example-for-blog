package org.example.sm2;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Optional;

public class SM2BCCipher {

    /**
     * SM2 算法加密数据
     *
     * @param data      待加密的数据
     * @param publicKey 加密数据的公钥，格式必须是 0x04||X||Y
     * @param C1C3C2    密文格式
     * @return 加密得到的密文
     */
    public static byte[] encrypt(byte[] data, byte[] publicKey, boolean C1C3C2)
            throws InvalidCipherTextException {
        X9ECParameters sm2p256v1 = Optional.ofNullable(ECNamedCurveTable.getByName("sm2p256v1"))
                .orElseThrow(() -> new IllegalArgumentException("未找到 SM2 曲线"));
        ECCurve curve = sm2p256v1.getCurve();
        ECPoint Q = curve.decodePoint(publicKey);
        ECPublicKeyParameters parameters = new ECPublicKeyParameters(Q, new ECDomainParameters(sm2p256v1));

        SM2Engine engine = new SM2Engine(C1C3C2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
        engine.init(true, new ParametersWithRandom(parameters));
        return engine.processBlock(data, 0, data.length);
    }

    /**
     * SM2 算法解密数据
     *
     * @param ciphertext 待解密的密文
     * @param privateKey 解密数据的私钥
     * @param C1C3C2     密文格式
     * @return 数据明文
     * @throws InvalidCipherTextException 密文非法
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] privateKey, boolean C1C3C2)
            throws InvalidCipherTextException {
        X9ECParameters sm2p256v1 = Optional.ofNullable(ECNamedCurveTable.getByName("sm2p256v1"))
                .orElseThrow(() -> new IllegalArgumentException("未找到 SM2 曲线"));
        ECPrivateKeyParameters parameters = new ECPrivateKeyParameters(
                new BigInteger(1, privateKey),
                new ECDomainParameters(sm2p256v1)
        );

        SM2Engine engine = new SM2Engine(C1C3C2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
        engine.init(false, parameters);
        return engine.processBlock(ciphertext, 0, ciphertext.length);
    }


    public static void main(String[] args) throws InvalidCipherTextException {
        byte[] data = "test data".getBytes();
        String publicKey = "04aa0a857024856bffd15fb0bbb58107059c2f0947b6859f42502dae9006481838c52ac25c044f3059a26bcba063ea4f1a904fdf7c22e9bbbea51f3d89d0f9c9fd";
        String privateKey = "79544a0b4116272629715026bcae2bcc5795c998259fb2659182ee6b4a0e8344";
        byte[] ciphertext = encrypt(data, Hex.decode(publicKey), true);
        System.out.println("密文：" + Hex.toHexString(ciphertext));
        byte[] plaintext = decrypt(ciphertext, Hex.decode(privateKey), true);
        System.out.println("明文：" + new String(plaintext));
    }
}
