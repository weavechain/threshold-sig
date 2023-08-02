package com.weavechain.sig;

import com.weavechain.curve25519.*;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@AllArgsConstructor
public class ThresholdSigEd25519 {

    @Getter
    private final int t;

    private final int n;

    private static final byte[] PREFIX = new byte[32];

    static {
        Arrays.fill(PREFIX, (byte)0xFF);
    }

    private static final Object syncObj = new Object();

    private static final ThreadLocal<Map<Set<Integer>, List<Scalar>>> cachedCoef = ThreadLocal.withInitial(ConcurrentHashMap::new);

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public static SecureRandom random() {
        return RANDOM.get();
    }

    public ThresholdSigEd25519Params generate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException, NoSuchProviderException {

        byte[] secret = new byte[32];
        random().nextBytes(secret);

        //private key build, this is not ok to be done centralized
        byte[] publicKey = createPublicKey(secret);
        Scalar privateKey = createPrivateKey(secret);

        //private key shares generation
        List<Scalar> privateShares = shamirSplit(privateKey, n);

        return new ThresholdSigEd25519Params(
                privateKey,
                publicKey,
                privateShares,
                null
        );
    }

    private List<Scalar> shamirSplit(Scalar secret, int n) {
        List<Scalar> result = new ArrayList<>();

        Polynom poly = new Polynom(t, secret);
        for (int i = 0; i < n; i++) {
            Scalar x = scalarFromBigInteger(BigInteger.valueOf(i + 1));
            result.add(poly.at(x));
        }

        return result;
    }

    public List<EdwardsPoint> gatherRi(ThresholdSigEd25519Params params, String toSign, Set<Integer> nodes) throws NoSuchAlgorithmException {
        //done by each node separately
        List<Scalar> Rs = new ArrayList<>();
        List<EdwardsPoint> Ri = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (nodes.contains(i)) {
                Scalar privateShare = params.getPrivateShares().get(i);
                Scalar rs = computeRs(privateShare, toSign);

                Rs.add(rs);
                EdwardsPoint res = mulBasepoint(rs);
                Ri.add(res);
            }
        }

        params.setSig(Rs);

        return Ri;
    }

    public Scalar computeRi(Scalar privateShare, String toSign) throws NoSuchAlgorithmException {
        return computeRs(privateShare, toSign);
    }

    public EdwardsPoint computeR(List<EdwardsPoint> Ri) {
        //done by coordinator
        EdwardsPoint R = Ri.get(0);
        for (int i = 1; i < t; i++) {
            R = R.add(Ri.get(i));
        }
        return R;
    }

    public Scalar computeK(byte[] publicKey, EdwardsPoint R, String toSign) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(R.compress().toByteArray());
        md.update(publicKey);
        md.update(toSign.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }

    public List<Scalar> gatherSignatures(ThresholdSigEd25519Params params, Scalar k, Set<Integer> nodes) {
        //done by each node
        List<Scalar> res = new ArrayList<>();
        int idx = 0;
        for (int i = 0; i < n; i++) {
            if (nodes.contains(i)) {
                Scalar privateShare = params.getPrivateShares().get(i);

                Scalar sig = params.getSig().get(idx);
                Scalar pt = computeSig(k, i + 1, privateShare, sig, nodes);
                res.add(pt);
                idx++;
            }
        }

        return res;
    }

    public Scalar computeSignature(int index, Scalar privateShare, Scalar sig, Scalar k, Set<Integer> nodes) {
        return computeSig(k, index, privateShare, sig, nodes);
    }

    public byte[] computeSignature(EdwardsPoint R, List<Scalar> res) throws IOException {
        //done by coordinator
        Scalar s = Scalar.ZERO;
        for (int i = 0; i < t; i++) {
            s = s.add(res.get(i));
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(R.compress().toByteArray());
        outputStream.write(s.toByteArray());
        return outputStream.toByteArray();
    }

    private Scalar computeSig(Scalar k, int index, Scalar privateShare, Scalar sig, Set<Integer> nodes) {
        List<Scalar> coef = getLagrangeCoef(n, nodes);
        return privateShare.multiply(coef.get(index - 1)).multiply(k).add(sig);
    }

    private Scalar computeRs(Scalar privateShare, String toSign) throws NoSuchAlgorithmException {
        byte[] rnd = new byte[64];
        random().nextBytes(rnd);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(PREFIX);
        md.update(privateShare.toByteArray());
        md.update(toSign.getBytes(StandardCharsets.UTF_8));
        md.update(rnd);

        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }

    public static EdwardsPoint mulBasepoint(Scalar input) {
        return Constants.ED25519_BASEPOINT.multiply(input);
    }

    private byte[] createPublicKey(byte[] secret) throws NoSuchAlgorithmException {
        byte[] hash = sha512(secret);
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        Scalar s = Scalar.fromBits(Arrays.copyOfRange(hash, 0, 32));
        return mulBasepoint(s).compress().toByteArray();
    }

    private Scalar createPrivateKey(byte[] secret) throws NoSuchAlgorithmException {
        byte[] hash = sha512(secret);
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        return Scalar.fromBits(Arrays.copyOfRange(hash, 0, 32));
    }

    private byte[] sha512(byte[] pk) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(pk);
        return md.digest();
    }

    public static List<Scalar> getLagrangeCoef(int size, Set<Integer> nodes) {
        List<Scalar> coef = cachedCoef.get().get(nodes);
        if (coef != null) {
            return coef;
        }

        List<Scalar> index = new ArrayList<>();
        List<Scalar> lagrangeCoef = new ArrayList<>();
        for (int i = 1; i <= size; i++) {
            index.add(scalarFromBigInteger(BigInteger.valueOf(i)));
            lagrangeCoef.add(Scalar.ONE);
        }

        for (int i = 1; i <= size; i++) {
            Scalar prodDiff = Scalar.ONE;
            Scalar factor = Scalar.ONE;
            for (int j = 1; j <= size; j++) {
                if (i != j && nodes.contains(j - 1)) {
                    Scalar dx = index.get(j - 1).subtract(index.get(i - 1));
                    factor = factor.multiply(index.get(j - 1));
                    prodDiff = prodDiff.multiply(dx);
                }
            }

            lagrangeCoef.set(i - 1, factor.multiply(prodDiff.invert()));
        }

        synchronized (syncObj) {
            cachedCoef.get().put(nodes, lagrangeCoef);
        }
        return lagrangeCoef;
    }

    public static boolean verify(byte[] publicKey, byte[] signature, byte[] signed) throws NoSuchAlgorithmException, InvalidEncodingException {
        byte[] R = Arrays.copyOfRange(signature, 0, 32);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(R);
        md.update(publicKey);
        md.update(signed);
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);

        EdwardsPoint negP = new CompressedEdwardsY(publicKey).decompress().negate();

        Scalar s = Scalar.fromBits(Arrays.copyOfRange(signature, 32, signature.length));
        EdwardsPoint pt = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(k, negP, s);

        byte[] repr = pt.compress().toByteArray();
        return Arrays.equals(repr, R);
    }

    public static Scalar scalarFromBigInteger(BigInteger value) {
        byte[] data = value.toByteArray();
        byte[] dest = new byte[32];
        int start = Math.max(0, data.length - 32);
        for (int j = start; j < data.length; j++) {
            dest[j - start] = data[data.length - 1 + start - j];
        }
        return Scalar.fromBits(dest);
    }

    public static class Polynom {

        private final List<Scalar> coefficients = new ArrayList<>();

        public Polynom(int order, Scalar a0) {
            coefficients.add(a0);
            for (int i = 1; i < order; i++) {
                byte[] input = new byte[32];
                random().nextBytes(input);
                coefficients.add(Scalar.fromBits(input));
            }
        }

        public Scalar at(Scalar x) {
            Scalar res = coefficients.get(0);

            Scalar cp = Scalar.ONE;
            for (int i = 1; i < coefficients.size(); i++) {
                cp = cp.multiply(x);
                res = coefficients.get(i).multiplyAndAdd(cp, res);
            }

            return res;
        }
    }
}