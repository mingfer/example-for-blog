package org.example.sm2;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class SM2CipherUtils {


    public byte[] C1C2C3ToC1C3C2(byte[] ciphertext) {
        final byte[] bytes = new byte[ciphertext.length];
        System.arraycopy(ciphertext, 0, bytes, 0, 65);
        System.arraycopy(ciphertext, ciphertext.length - 32, bytes, 65, 32);
        System.arraycopy(ciphertext, 65, bytes, 97, ciphertext.length - 97);
        return bytes;
    }


    public byte[] C1C3C2ToC1C2C3(byte[] ciphertext) {
        final byte[] bytes = new byte[ciphertext.length];
        System.arraycopy(ciphertext, 0, bytes, 0, 65);
        System.arraycopy(ciphertext, 97, bytes, 65, ciphertext.length - 97);
        System.arraycopy(ciphertext, 65, bytes, ciphertext.length - 32, 32);
        return bytes;
    }


    public static byte[] C1C3C2ToDer(byte[] ciphertext) throws IOException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        final byte[] point = new byte[65];
        System.arraycopy(ciphertext, 0, point, 0, 65);
        final ECPoint ecPoint = spec.getCurve().decodePoint(point);
        final byte[] m = new byte[32];
        System.arraycopy(ciphertext, 65, m, 0, 32);
        final byte[] c = new byte[ciphertext.length - 65 - 32];
        System.arraycopy(ciphertext, 65 + 32, c, 0, ciphertext.length - 65 - 32);
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(ecPoint.getAffineXCoord().toBigInteger()));
        vector.add(new ASN1Integer(ecPoint.getAffineYCoord().toBigInteger()));
        vector.add(new DEROctetString(m));
        vector.add(new DEROctetString(c));
        final ASN1Sequence sequence = new DERSequence(vector);
        return sequence.getEncoded();
    }

    public static byte[] derToC1C3C2(byte[] cipher) {
        try {
            final ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(cipher));
            final ASN1Primitive object = stream.readObject();
            final ASN1Sequence sequence = (ASN1Sequence) object;
            final ASN1Integer x = (ASN1Integer) sequence.getObjectAt(0);
            final ASN1Integer y = (ASN1Integer) sequence.getObjectAt(1);
            final DEROctetString m = (DEROctetString) sequence.getObjectAt(2);
            final DEROctetString c = (DEROctetString) sequence.getObjectAt(3);
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
            final ECPoint ecPoint = spec.getCurve().createPoint(x.getPositiveValue(), y.getPositiveValue());
            final byte[] c1 = ecPoint.getEncoded(false);
            final byte[] c3 = m.getOctets();
            final byte[] c2 = c.getOctets();
            return Arrays.concatenate(c1, c3, c2);
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

}
