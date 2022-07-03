import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class aes{
	// aes-128 加密，输入 明文 16 bytes array + 密钥 16 bytes array 输出 密文 16 bytes array
	static byte[] en128(byte[] t,byte[] k){
		byte[] ke = Utils.keyExpansion128(k);
		Utils.addRoundKey(t,ke,0);
		for(int i=1;i<=9;i++){
			for(int j=0;j<16;j++)
				t[j]=Utils.subBytes(t[j]);
			t = Utils.shiftRow(t);
			t = Utils.mixColumn(t);
			Utils.addRoundKey(t,ke,i*16);
		}
		for(int j=0;j<16;j++)
			t[j]=Utils.subBytes(t[j]);
		t = Utils.shiftRow(t);
		Utils.addRoundKey(t,ke,160);
		return t;
	}
	// aes-192 加密，输入 明文 16 bytes array + 密钥 24 bytes array 输出 密文 16 bytes array
	static byte[] en192(byte[] t,byte[] k){
		byte[] ke = Utils.keyExpansion192(k);
		Utils.addRoundKey(t,ke,0);
		for(int i=1;i<=11;i++){
			for(int j=0;j<16;j++)
				t[j]=Utils.subBytes(t[j]);
			t = Utils.shiftRow(t);
			t = Utils.mixColumn(t);
			Utils.addRoundKey(t,ke,i*16);
		}
		for(int j=0;j<16;j++)
			t[j]=Utils.subBytes(t[j]);
		t = Utils.shiftRow(t);
		Utils.addRoundKey(t,ke,192);
		return t;
	}
	// aes-256 加密，输入 明文 16 bytes array + 密钥 32 bytes array 输出 密文 16 bytes array
	static byte[] en256(byte[] t,byte[] k){
		byte[] ke = Utils.keyExpansion256(k);
		Utils.addRoundKey(t,ke,0);
		for(int i=1;i<=13;i++){
			for(int j=0;j<16;j++)
				t[j]=Utils.subBytes(t[j]);
			t = Utils.shiftRow(t);
			t = Utils.mixColumn(t);
			Utils.addRoundKey(t,ke,i*16);
		}
		for(int j=0;j<16;j++)
			t[j]=Utils.subBytes(t[j]);
		t = Utils.shiftRow(t);
		Utils.addRoundKey(t,ke,224);
		return t;
	}


	// aes-128 解密，输入 密文 16 bytes array + 密钥 16 bytes array 输出 明文 16 bytes array
	static byte[] de128(byte[] c,byte[] k){	
		byte[] ke = Utils.keyExpansion128(k);
		Utils.addRoundKey(c,ke,160);
		c = Utils.invShiftRow(c);
		for(int j=0;j<16;j++)
			c[j]=Utils.invSubBytes(c[j]);
		for(int i=9;i>=1;i--){
			Utils.addRoundKey(c,ke,i*16);
			c = Utils.invMixColumn(c);
			c = Utils.invShiftRow(c);
			for(int j=0;j<16;j++)
				c[j]=Utils.invSubBytes(c[j]);
		}
		Utils.addRoundKey(c,ke,0);
		return c;
	}

	// aes-192 解密，输入 密文 16 bytes array + 密钥 24 bytes array 输出 明文 16 bytes array
	static byte[] de192(byte[] c,byte[] k){
		byte[] ke = Utils.keyExpansion192(k);
		Utils.addRoundKey(c,ke,192);
		c = Utils.invShiftRow(c);
		for(int j=0;j<16;j++)
			c[j]=Utils.invSubBytes(c[j]);
		for(int i=11;i>=1;i--){
			Utils.addRoundKey(c,ke,i*16);
			c = Utils.invMixColumn(c);
			c = Utils.invShiftRow(c);
			for(int j=0;j<16;j++)
				c[j]=Utils.invSubBytes(c[j]);
		}
		Utils.addRoundKey(c,ke,0);
		return c;
	}

	// aes-256 解密，输入 密文 16 bytes array + 密钥 32 bytes array 输出 明文 16 bytes array
	static byte[] de256(byte[] c,byte[] k){
		byte[] ke = Utils.keyExpansion256(k);
		Utils.addRoundKey(c,ke,224);
		c = Utils.invShiftRow(c);
		for(int j=0;j<16;j++)
			c[j]=Utils.invSubBytes(c[j]);
		for(int i=13;i>=1;i--){
			Utils.addRoundKey(c,ke,i*16);
			c = Utils.invMixColumn(c);
			c = Utils.invShiftRow(c);
			for(int j=0;j<16;j++)
				c[j]=Utils.invSubBytes(c[j]);
		}
		Utils.addRoundKey(c,ke,0);
		return c;
	}


	public static void main(String[] args) {
		//Scanner scan = new Scanner(System.in);
		String[] method = Utils.parseArgs(args);
		String eOd = method[0];
		String nnn = method[1];
		String kinput = method[2];
		// System.out.println("PLAINTEXT or CIPHER:(example: 00112233445566778899aabbccddeeff)");
		// String tinput = scan.nextLine();
		// byte[] t = Utils.string2byteArray16(tinput);
		byte[] t = new byte[16];
		try{
			System.in.read(t);
		}
		catch(IOException e){
			e.printStackTrace();
		}

		if(nnn.equals("128")){
			byte[] k = Utils.string2byteArray16(kinput);
			if(eOd.equals("d"))
				t = de128(t,k);
			else
				t = en128(t,k);
		}
		else if (nnn.equals("192")){
			byte[] k = Utils.string2byteArray24(kinput);
			if(eOd.equals("d"))
				t = de192(t,k);
			else
				t = en192(t,k);
		}
		else if (nnn.equals("256")){
			byte[] k = Utils.string2byteArray32(kinput);
			if(eOd.equals("d"))
				t = de256(t,k);
			else
				t = en256(t,k);
		}

		// System.out.println();
		// System.out.println("RESULT:");
		// for(int i=0;i<16;i++){
		// 	System.out.print(Utils.byte2string(t[i]));
		// }
		try{
			System.out.write(t);
		}
		catch(IOException e){
			e.printStackTrace();
		}
		// System.out.println();

	}
}

class Utils{

	//FG域的乘法
	static byte FGmultiply(byte a,byte b){
		byte result = (byte)0x00;
		//将b的每一位与a的每一位相乘，a一旦超出一个字节则模0x011b
		for(int i=0;i<8;i++){
			result ^= ((b >> i) & 0x01) * a;
			a = ((a & (byte)0x80) != (byte)0x00) ? (byte)((byte)0x1b ^ (byte)(a<<1)) : (byte)(a<<1);
		}
		return result;
	}
	//FG域的除法，返回数组，arr[0]为商，arr[1]为余数
	static byte[] FGdiv(char a,char b){
		//检查a是否更小，得出余数
		int am=8,bm=8;
		while(((1<<am)&a)==0 && am>=0)
			am--;
		while(((1<<bm)&b)==0 && bm>=0)
			bm--;
		if(am<bm)
			return new byte[]{0,(byte)a};

		//将b左移，相减得到新的a
		int deg = am - bm;
		a = (char)((char)a ^ (char)(b << deg));
		//递归
		byte[] br = FGdiv(a,b);
		//商增加
		br[0] |= (1 << deg);
		return br;
	}
	//自然数的扩展欧几里得算法
	static int exgcd(int a,int b,int[] arr){
		if(b == 0){
			arr[0]=1;
			arr[1]=0;
			return a;
		}
		int g = exgcd(b,a%b,arr);
		int t = arr[0];
		arr[0]=arr[1];//x1=y2
		arr[1]=t-(a/b)*arr[1];//y1=x2-[a/b]*y2
		return g;
	}
	//FG域的扩展欧几里得算法，仅需替换四则运算为FG域的相应运算
	static byte FGexgcd(char a,char b,byte[] arr){
		//System.out.println(a+0);
		if(b == 0){
			//System.out.println("found");
			arr[0]=(byte)0x01;
			arr[1]=(byte)0x00;
			return (byte)a;
		}
		byte g = FGexgcd(b,(char)Utils.FGdiv(a,b)[1],arr);
		//System.out.println(g&0xff);
		byte t = arr[0];
		arr[0]=arr[1];
		arr[1]=(byte)( t ^ Utils.FGmultiply(Utils.FGdiv(a,b)[0],arr[1]));
		return g;
	}
	//FG域的求逆 因为gcd(0x11B,x)==1，用FGexgcd得到[s,t]，其中s·0x11B + t·x = 1,则有 t·x = 1 mod 0x11B，返回t即可
	static byte FGinverse(byte x){
		char a = (char)0x11B;
		char b = (char)(x & 0xff);
		//System.out.println(b+0);
		byte[] arr = {(byte)0x00,(byte)0x00};
		Utils.FGexgcd(a,b,arr);
		return(arr[1]);

	}
	static int getBit(byte b,int i){
		return ((b>>i) & 0x01);
	}
	//字节代换层
	static byte subBytes(byte x){
		//采用计算而非查S盒
		x = FGinverse(x);
		byte c = (byte)0x63;
		byte result = (byte)0x00;
		//通过循环得到result的每一位
		for(int i=0;i<8;i++){
			result = (byte)( result | ((getBit(x,i)^getBit(x,(i+4)%8)^getBit(x,(i+5)%8)^getBit(x,(i+6)%8)^getBit(x,(i+7)%8)^getBit(c,i)) << i));
		}
		return result;
	}
	//逆向字节代换层
	static byte invSubBytes(byte x){
		byte d = (byte)0x05;
		byte result = (byte)0x00;
		for(int i=0;i<8;i++){
			result = (byte)( result | ((getBit(x,(i+2)%8)^getBit(x,(i+5)%8)^getBit(x,(i+7)%8)^getBit(d,i)) << i));
		}
		result = FGinverse(result);
		return result;
	}
	//行移位变换
	static byte[] shiftRow(byte[] a){	
		byte[] b = new byte[16];
		for(int i=0;i<4;i++){
			b[i*4]=a[i*4];
			b[i*4+1]=a[(i*4+5)%16];
			b[i*4+2]=a[(i*4+10)%16];
			b[i*4+3]=a[(i*4+15)%16];
		}
		return b;

	}
	//逆向行移位变换
	static byte[] invShiftRow(byte[] a){
		byte[] b = new byte[16];
		for(int i=0;i<4;i++){
			b[i*4]=a[i*4];
			b[i*4+1]=a[(i*4+13)%16];
			b[i*4+2]=a[(i*4+10)%16];
			b[i*4+3]=a[(i*4+7)%16];
		}
		return b;
	}

	//列混淆变换
	static byte[] mixColumn(byte[] a){
		byte[] b = new byte[16];
		for(int i=0;i<4;i++){
			byte g = (byte)( a[i*4] ^ a[i*4+1] ^ a[i*4+2] ^ a[i*4+3]);
			for(int j=0;j<4;j++){
				b[i*4+j]=(byte)(g ^ a[i*4+j] ^ (((a[i*4+j] & (byte)0x80) != (byte)0x00) ? (byte)((byte)0x1b ^ (byte)(a[i*4+j]<<1)) : (byte)(a[i*4+j]<<1)) ^ (((a[i*4+(j+1)%4] & (byte)0x80) != (byte)0x00) ? (byte)((byte)0x1b ^ (byte)(a[i*4+(j+1)%4]<<1)) : (byte)(a[i*4+(j+1)%4]<<1)));
			}
		}
		return b;
	}
	//逆向列混淆变换
	static byte[] invMixColumn(byte[] a){
		byte[] b = new byte[16];
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++){
				b[i*4+j]=(byte)( Utils.FGmultiply(a[i*4+j],(byte)0x0E) ^ Utils.FGmultiply(a[i*4+(j+1)%4],(byte)0x0B) ^ Utils.FGmultiply(a[i*4+(j+2)%4],(byte)0x0D) ^ Utils.FGmultiply(a[i*4+(j+3)%4],(byte)0x09));
			}
		}
		return b;
	}


	//密钥加法层
	static void addRoundKey(byte[] a,byte[] k,int start){
		for(int i=0;i<16;i++){
			a[i] = (byte)(a[i] ^ k[i+start]);
		}
	}
	//密钥编排之128位密钥，10轮迭代得到(4+10*4)4=/11个子密钥，返回11*16=176bytes的子密钥
	static byte[] keyExpansion128(byte[] k){
		byte[] ke = new byte[176];
		//轮系数
		byte rc = (byte)0x01;
		//轮密钥0
		for(int i=0;i<16;i++)
			ke[i]=k[i];
		//轮密钥1 ~ 轮密钥10 每轮计算4个word 一个word是4bytes
		for(int r=1;r<=10;r++){
			//对前一个word发动増殖するG
			for(int i=0;i<4;i++){
				ke[r*16+i]=ke[r*16-4+(i+1)%4];
				ke[r*16+i]=Utils.subBytes(ke[r*16+i]);
			}
			ke[r*16] = (byte)( ke[r*16] ^ rc );
			//rc变换
			rc=Utils.FGmultiply(rc,(byte)0x02);
			//完成首个word，在g的基础上加上前数第4个word
			for(int i=0;i<4;i++){
				ke[r*16+i] = (byte)(ke[r*16+i] ^ ke[r*16-16+i]);
				//System.out.println("ke["+(r*16+i)+"]="+byte2string(ke[r*16+i]));
			}
			//剩下3个word
			for(int m=1;m<=3;m++){
				for(int i=0;i<4;i++){
					ke[r*16+m*4+i] = (byte)(ke[r*16+m*4-4+i] ^ ke[r*16-16+m*4+i]);
				}
			}
		}
		return ke;
	}

	//密钥编排之192位密钥，8轮迭代得到(6+7*6+4)/4=13个子密钥，返回13*16=208bytes的子密钥
	static byte[] keyExpansion192(byte[] k){
		byte[] ke = new byte[208];
		//轮系数
		byte rc = (byte)0x01;
		//轮密钥0
		for(int i=0;i<24;i++)
			ke[i]=k[i];
		//轮密钥1 ~ 轮密钥8 每轮计算6个word 一个word是4bytes
		for(int r=1;r<=8;r++){
			//对前一个word发动増殖するG
			for(int i=0;i<4;i++){
				ke[r*24+i]=ke[r*24-4+(i+1)%4];
				ke[r*24+i]=Utils.subBytes(ke[r*24+i]);
			}
			ke[r*24] = (byte)( ke[r*24] ^ rc );
			//rc变换
			rc=Utils.FGmultiply(rc,(byte)0x02);
			//完成首个word，在g的基础上加上前数第6个word
			for(int i=0;i<4;i++){
				ke[r*24+i] = (byte)(ke[r*24+i] ^ ke[r*24-24+i]);
			}
			//剩下5个word
			for(int m=1;m<=5;m++){
				for(int i=0;i<4;i++){
					if(r*24+m*4+i<208)
						ke[r*24+m*4+i] = (byte)(ke[r*24+m*4-4+i] ^ ke[r*24-24+m*4+i]);
				}
			}
		}
		return ke;
	}

	//密钥编排之256位密钥，7轮迭代得到(8+6*8+4)/4=15个子密钥，返回15*16=240bytes的子密钥
	static byte[] keyExpansion256(byte[] k){
		byte[] ke = new byte[240];
		//轮系数
		byte rc = (byte)0x01;
		//轮密钥0
		for(int i=0;i<32;i++)
			ke[i]=k[i];
		//轮密钥1 ~ 轮密钥7 每轮计算8个word 一个word是4bytes
		for(int r=1;r<=7;r++){
			//对前一个word发动増殖するG
			for(int i=0;i<4;i++){
				ke[r*32+i]=ke[r*32-4+(i+1)%4];
				ke[r*32+i]=Utils.subBytes(ke[r*32+i]);
			}
			ke[r*32] = (byte)( ke[r*32] ^ rc );
			//rc变换
			rc=Utils.FGmultiply(rc,(byte)0x02);
			//完成首个word，在g的基础上加上前数第8个word
			for(int i=0;i<4;i++){
				ke[r*32+i] = (byte)(ke[r*32+i] ^ ke[r*32-32+i]);
			}
			//剩下7个word
			for(int m=1;m<=7;m++){
				for(int i=0;i<4;i++){
					if(r*32+m*4+i<240){
						if(m==4)
							ke[r*32+m*4+i] = (byte)(Utils.subBytes(ke[r*32+m*4-4+i]) ^ ke[r*32-32+m*4+i]);
						else
							ke[r*32+m*4+i] = (byte)(ke[r*32+m*4-4+i] ^ ke[r*32-32+m*4+i]);
					}
				}
			}
		}
		return ke;
	}

	// convert hex string to 16 bytes array
	static byte[] string2byteArray16(String s){
		byte[] b = new byte[16];
		for(int i=0;i<16;i++){
			char c1=s.charAt(i*2);
			char c2=s.charAt(i*2+1);
			if(c1>='0' && c1 <='9')
				b[i] = (byte)((c1-48)<<4);
			else if(c1>='A' && c1<='F')
				b[i] = (byte)((c1-55)<<4);
			else if(c1>='a' && c1<='f')
				b[i] = (byte)((c1-87)<<4);
			else
				b[i] = (byte)0x00;
			if(c2>='0' && c2 <='9')
				b[i] = (byte)((c2-48)|b[i]);
			else if(c2>='A' && c2<='F')
				b[i] = (byte)((c2-55)|b[i]);
			else if(c2>='a' && c2<='f')
				b[i] = (byte)((c2-87)|b[i]);
			else
				b[i] = (byte)0x00;
		}
		return b;
	}

	// convert hex string to 24 bytes array
	static byte[] string2byteArray24(String s){
		byte[] b = new byte[24];
		for(int i=0;i<24;i++){
			char c1=s.charAt(i*2);
			char c2=s.charAt(i*2+1);
			if(c1>='0' && c1 <='9')
				b[i] = (byte)((c1-48)<<4);
			else if(c1>='A' && c1<='F')
				b[i] = (byte)((c1-55)<<4);
			else if(c1>='a' && c1<='f')
				b[i] = (byte)((c1-87)<<4);
			else
				b[i] = (byte)0x00;
			if(c2>='0' && c2 <='9')
				b[i] = (byte)((c2-48)|b[i]);
			else if(c2>='A' && c2<='F')
				b[i] = (byte)((c2-55)|b[i]);
			else if(c2>='a' && c2<='f')
				b[i] = (byte)((c2-87)|b[i]);
			else
				b[i] = (byte)0x00;
		}
		return b;
	}

		// convert hex string to 32 bytes array
		static byte[] string2byteArray32(String s){
			byte[] b = new byte[32];
			for(int i=0;i<32;i++){
				char c1=s.charAt(i*2);
				char c2=s.charAt(i*2+1);
				if(c1>='0' && c1 <='9')
					b[i] = (byte)((c1-48)<<4);
				else if(c1>='A' && c1<='F')
					b[i] = (byte)((c1-55)<<4);
				else if(c1>='a' && c1<='f')
					b[i] = (byte)((c1-87)<<4);
				else
					b[i] = (byte)0x00;
				if(c2>='0' && c2 <='9')
					b[i] = (byte)((c2-48)|b[i]);
				else if(c2>='A' && c2<='F')
					b[i] = (byte)((c2-55)|b[i]);
				else if(c2>='a' && c2<='f')
					b[i] = (byte)((c2-87)|b[i]);
				else
					b[i] = (byte)0x00;
			}
			return b;
		}



	static String byte2string(byte b){
		char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char[] s = new char[2];
		s[0] = hex[(b >> 4) & 0x0f];
		s[1] = hex[b & 0x0f];
		return(new String(s));
	}
	static void showHex(byte b){
		System.out.println("0x"+byte2string(b));
	}

	static void showHelp(PrintStream out){
        out.println("Usage:");
        out.println("    -h,--help");
        out.println("    -e,--encrypt");
        out.println("    -d,--decrypt");
		out.println("    -aes-128-ecb");
		out.println("    -aes-192-ecb");
		out.println("    -aes-256-ecb");
		out.println("    -K <val>");

    }
    static String[] parseArgs(String[] args){
		String[] method = new String[3];
		method[0] = "e";
		method[1] = "128";
		method[2] = "";
        try{
            Map<String, List<String>> params = ArgsParser.parse(args);
            List<String> optionkeys = new ArrayList<String>(params.keySet());
            List<String> options=null;
            if(params.get("h")!=null || params.get("-help")!=null){
                showHelp(System.out);
                System.exit(0);
            }
            else{
                if((options=params.get("d"))!=null || (options=params.get("-decrypt"))!=null){
                    if(options.size()==0){
                        method[0] = "d";
                        optionkeys.remove("d");
                        optionkeys.remove("-decrypt");
                    }
                    else{
                        throw new IllegalArgumentException("Error at argument: -d or --decrypt");
                    }
                }
				else if((options=params.get("e"))!=null || (options=params.get("-encrypt"))!=null){
					if(options.size()==0){
						method[0] = "e";
						optionkeys.remove("e");
						optionkeys.remove("-encrypt");
					}
					else{
						throw new IllegalArgumentException("Error at argument: -e or --encrypt");
					}
				}
				else{
					System.err.println("[!]Using -e as default method");
				}
				if((options=params.get("aes-128-ecb"))!=null){
					if(options.size()==0){
						method[1] = "128";
						optionkeys.remove("aes-128-ecb");
					}
					else{
						throw new IllegalArgumentException("Error at argument: -aes-128-ecb");
					}
				}
				else if((options=params.get("aes-192-ecb"))!=null){
					if(options.size()==0){
						method[1] = "192";
						optionkeys.remove("aes-192-ecb");
					}
					else{
						throw new IllegalArgumentException("Error at argument: -aes-192-ecb");
					}
				}
				else if((options=params.get("aes-256-ecb"))!=null){
					if(options.size()==0){
						method[1] = "256";
						optionkeys.remove("aes-256-ecb");
					}
					else{
						throw new IllegalArgumentException("Error at argument: -aes-256-ecb");
					}
				}
				else{
					System.err.println("[!]Using -aes-128-ecb as default method");
				}
				if((options=params.get("K"))!=null){
                    if(options.size()==1){
                        String key=options.get(0);
                        String keyPattern = "^[A-Fa-f0-9]{32}|[A-Fa-f0-9]{48}|[A-Fa-f0-9]{64}$";
                        if(!Pattern.matches(keyPattern, key)){
                            System.err.println("Invalid value: -K");
							key += "0000000000000000000000000000000000000000000000000000000000000000";
						}
                        method[2] = key;
                        optionkeys.remove("K");
                    }
                    else{
                        throw new IllegalArgumentException("Error at argument: -K");
                    }
                }else{
                    throw new IllegalArgumentException("please specify a key");
                }
            }
            if(!optionkeys.isEmpty()){
                System.err.println("[!]Ignored arguments:");
                for(String optionkey:optionkeys){
                    System.out.print(" "+optionkey);
                }
                System.out.println();
            }
			

        }catch (IllegalArgumentException e){
            System.err.println("[-]"+e.getMessage());
            showHelp(System.err);
            System.exit(1);
        }
		return method;
    }

}
class ArgsParser {
    public static Map<String, List<String>> parse(String[] args) throws IllegalArgumentException {
        final Map<String, List<String>> params = new HashMap<>();

        List<String> options = null;
        boolean endOption = false;
        for (int i = 0; i < args.length; i++) {
            final String a = args[i];

            if (a.charAt(0) == '-' && !endOption) {
                if (a.length() < 2) {
                    throw new IllegalArgumentException("Error at argument: " + a);
                }
                if(a.equals("--")){
                    endOption=true;
                    continue;
                }
                options = new ArrayList<>();
                if (a.length() > 2 && a.charAt(2)<='9'&&a.charAt(2)>='0'){
                        options.add(a.substring(2));
                        params.put(a.charAt(1)+"", options);
                }
                else if(a.length() > 3 && a.contains("=")&&a.indexOf("=")>1){
                    options.add(a.split("=")[1]);
                    params.put(a.split("=")[0].substring(1), options);
                }
                else{
                    params.put(a.substring(1), options);
                }
            } else if (options != null) {
                options.add(a);
            } else {
                throw new IllegalArgumentException("Illegal parameter usage");
            }
        }
        return params;
    }
}
