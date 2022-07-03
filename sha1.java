import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class sha1 {
    // 存放哈希值的缓冲区大小，单位为字节
    private static final int HASH_LENGTH = 20;

    // 分割消息后，每个分组的大小，单位为字节
    private static final int DATA_LENGTH = 64;

    // 存放消息分组的缓冲区
    private byte[] buffer;

    // buffer[]目前的有效数据长度
    private int buffered;

    // 已计算的数据量，单位为字节
    private long count;

    // 存放哈希值的缓冲区
    private int[] digest;
    // 存放消息分组的缓冲区
    private int[] data;
    // 消息调度中计算的 80*4 bytes 的数据
    private int[] z;
    // 临时存放 用于转换
    private byte[] tmp;

    // 从标准输入读取数据，进行SHA1计算，输出到标准输出
    public static void main(String[] args) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[32 * 1024];

            int bytesRead;
            while ((bytesRead = System.in.read(buffer)) > 0) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] bytes = baos.toByteArray();
            System.out.write(hash(bytes));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 构造函数
    public sha1() {
        buffer = new byte[DATA_LENGTH];
        digest = new int[HASH_LENGTH / 4];
        data = new int[DATA_LENGTH / 4];
        tmp = new byte[DATA_LENGTH];
        z = new int[80];
        engineReset();
    }

    // 输入一个字节数组，计算其哈希值，并返回一个字节数组
    public static byte[] hash(byte[] input) {
        sha1 sha1 = new sha1();
        return sha1.engineDigest(input, 0, input.length);
    }

    // 重置数据
    private void engineReset() {
        buffered = 0;
        count = 0;
        digest[0] = 0x67452301;
        digest[1] = 0xefcdab89;
        digest[2] = 0x98badcfe;
        digest[3] = 0x10325476;
        digest[4] = 0xc3d2e1f0;

        // 归零
        for (int i = 0; i < DATA_LENGTH; i++) {
            tmp[i] = 0;
            buffer[i] = 0;
        }
        for (int i = 0; i < DATA_LENGTH / 4; i++)
            data[i] = 0;
        for (int i = 0; i < 80; i++)
            z[i] = 0;
    }

    // 计算摘要的全过程
    byte[] engineDigest(byte[] input, int offset, int length) {
        count += length;

        int datalen = DATA_LENGTH;
        int remainder;

        // 512位的整块计算
        while (length >= (remainder = datalen - buffered)) {
            System.arraycopy(input, offset, buffer, buffered, remainder);
            engineTransform(buffer);
            length -= remainder;
            offset += remainder;
            buffered = 0;
        }

        //最后若有不足512位的数据，则放入缓冲区
        if (length > 0) {
            System.arraycopy(input, offset, buffer, buffered, length);
            buffered += length;
        }

        //完成剩下的计算

        int pos = buffered;
        if (pos != 0)
            System.arraycopy(buffer, 0, tmp, 0, pos);

        tmp[pos++] = (byte) 0x80;

        if (pos > DATA_LENGTH - 8) {
            while (pos < DATA_LENGTH)
                tmp[pos++] = 0;

            byte2int(tmp, 0, data, 0, DATA_LENGTH / 4);
            transform(data);
            pos = 0;
        }

        while (pos < DATA_LENGTH - 8)
            tmp[pos++] = 0;

        byte2int(tmp, 0, data, 0, (DATA_LENGTH / 4) - 2);

        // Big endian
        long bc = count * 8;
        data[14] = (int) (bc >>> 32);
        data[15] = (int) bc;

        transform(data);

        byte buf[] = new byte[HASH_LENGTH];

        // Big endian
        int off = 0;
        for (int i = 0; i < HASH_LENGTH / 4; ++i) {
            int d = digest[i];
            buf[off++] = (byte) (d >>> 24);
            buf[off++] = (byte) (d >>> 16);
            buf[off++] = (byte) (d >>> 8);
            buf[off++] = (byte) d;
        }

        engineReset();
        return buf;
    }

    // 处理消息分组，byte[] buffer转到int[] data,然后计算哈希
    private void engineTransform(byte[] in) {
        byte2int(in, 0, data, 0, DATA_LENGTH / 4);
        transform(data);
    }

    // byte转int版本的System.arraycopy.
    private static void byte2int(byte[] src, int srcOffset,
            int[] dst, int dstOffset, int length) {
        while (length-- > 0) {
            // Big endian
            dst[dstOffset++] = (src[srcOffset++] << 24) |
                    ((src[srcOffset++] & 0xFF) << 16) |
                    ((src[srcOffset++] & 0xFF) << 8) |
                    (src[srcOffset++] & 0xFF);
        }
    }

    //4个阶段各自的轮函数
    
    private static int f1(int a, int b, int c) {
        return (c ^ (a & (b ^ c))) + 0x5A827999;
    }

    private static int f2(int a, int b, int c) {
        return (a ^ b ^ c) + 0x6ED9EBA1;
    }

    private static int f3(int a, int b, int c) {
        return ((a & b) | (c & (a | b))) + 0x8F1BBCDC;
    }

    private static int f4(int a, int b, int c) {
        return (a ^ b ^ c) + 0xCA62C1D6;
    }

    //压缩函数，输入512位分组，将digest替换为新的160位哈希值
    private void transform(int[] X) {
        //载入上个消息分组的处理后的输出值
        int A = digest[0];
        int B = digest[1];
        int C = digest[2];
        int D = digest[3];
        int E = digest[4];
        //由X得到W
        int W[] = z;
        for (int i = 0; i < 16; i++)
            W[i] = X[i];

        for (int i = 16; i < 80; i++) {
            int j = W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3];
            W[i] = j;
            W[i] = (j << 1) | (j >>> -1);
        }
        //80轮操作
        E += ((A << 5) | (A >>> -5)) + f1(B, C, D) + W[0];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f1(A, B, C) + W[1];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f1(E, A, B) + W[2];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f1(D, E, A) + W[3];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f1(C, D, E) + W[4];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f1(B, C, D) + W[5];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f1(A, B, C) + W[6];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f1(E, A, B) + W[7];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f1(D, E, A) + W[8];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f1(C, D, E) + W[9];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f1(B, C, D) + W[10];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f1(A, B, C) + W[11];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f1(E, A, B) + W[12];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f1(D, E, A) + W[13];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f1(C, D, E) + W[14];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f1(B, C, D) + W[15];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f1(A, B, C) + W[16];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f1(E, A, B) + W[17];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f1(D, E, A) + W[18];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f1(C, D, E) + W[19];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f2(B, C, D) + W[20];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f2(A, B, C) + W[21];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f2(E, A, B) + W[22];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f2(D, E, A) + W[23];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f2(C, D, E) + W[24];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f2(B, C, D) + W[25];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f2(A, B, C) + W[26];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f2(E, A, B) + W[27];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f2(D, E, A) + W[28];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f2(C, D, E) + W[29];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f2(B, C, D) + W[30];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f2(A, B, C) + W[31];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f2(E, A, B) + W[32];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f2(D, E, A) + W[33];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f2(C, D, E) + W[34];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f2(B, C, D) + W[35];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f2(A, B, C) + W[36];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f2(E, A, B) + W[37];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f2(D, E, A) + W[38];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f2(C, D, E) + W[39];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f3(B, C, D) + W[40];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f3(A, B, C) + W[41];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f3(E, A, B) + W[42];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f3(D, E, A) + W[43];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f3(C, D, E) + W[44];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f3(B, C, D) + W[45];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f3(A, B, C) + W[46];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f3(E, A, B) + W[47];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f3(D, E, A) + W[48];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f3(C, D, E) + W[49];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f3(B, C, D) + W[50];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f3(A, B, C) + W[51];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f3(E, A, B) + W[52];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f3(D, E, A) + W[53];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f3(C, D, E) + W[54];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f3(B, C, D) + W[55];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f3(A, B, C) + W[56];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f3(E, A, B) + W[57];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f3(D, E, A) + W[58];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f3(C, D, E) + W[59];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f4(B, C, D) + W[60];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f4(A, B, C) + W[61];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f4(E, A, B) + W[62];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f4(D, E, A) + W[63];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f4(C, D, E) + W[64];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f4(B, C, D) + W[65];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f4(A, B, C) + W[66];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f4(E, A, B) + W[67];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f4(D, E, A) + W[68];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f4(C, D, E) + W[69];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f4(B, C, D) + W[70];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f4(A, B, C) + W[71];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f4(E, A, B) + W[72];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f4(D, E, A) + W[73];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f4(C, D, E) + W[74];
        C = ((C << 30) | (C >>> -30));
        E += ((A << 5) | (A >>> -5)) + f4(B, C, D) + W[75];
        B = ((B << 30) | (B >>> -30));
        D += ((E << 5) | (E >>> -5)) + f4(A, B, C) + W[76];
        A = ((A << 30) | (A >>> -30));
        C += ((D << 5) | (D >>> -5)) + f4(E, A, B) + W[77];
        E = ((E << 30) | (E >>> -30));
        B += ((C << 5) | (C >>> -5)) + f4(D, E, A) + W[78];
        D = ((D << 30) | (D >>> -30));
        A += ((B << 5) | (B >>> -5)) + f4(C, D, E) + W[79];
        C = ((C << 30) | (C >>> -30));

        //新的哈希值存放到digest中
        digest[0] += A;
        digest[1] += B;
        digest[2] += C;
        digest[3] += D;
        digest[4] += E;
    }

}