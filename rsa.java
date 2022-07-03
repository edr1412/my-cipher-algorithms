import java.util.Scanner;
//教科书式的RSA
public class rsa{
	//Miller-Rabin 素性测试
	public static boolean isPrime(long n){
		if(n == 2 || n == 3)
			return true;

		//n -1 = 2 ^ u * q
		long nt=n-1;
		int k=0;	
		while(nt%2==0){
			nt=nt/2;
			k++;
		}
		long q=nt;

		//取若干基元素a 事实上只需要几个特定的a通过了就可判断是素数
		long[] a;

		if(n<1373653)
			a=new long[]{2,3};
		else if(n<4294967296L)
			a=new long[]{2,7,61};
		else
			a=new long[]{2,325,9375,28178,450775,9780504,1795265022};


	//用多个a进行多轮测试，看能否判断n是合数
	outer:for(int i=0;i<a.length;i++){

			//验证a^q mod n是否≡±1，若不是则再不断平方直到a^(q)^(2^(k-1))，若还是没出现-1，才可判断n是合数
			long as=squareAndMutiply(a[i],q,n);
			if(as==1 || as == n-1)
				continue;
			for(int j=1;j<k;j++){
				as=(as*as)%n;
				if(as==n-1){
					continue outer;
				}
				//出现1，则再也不能平方得到-1，可提前确定n是合数
				if(as==1){
					return false;
				}
				
			}

			return false;
		}
		return true;
	}
	//平方求冪算法，快速计算 a^q mod n
	public static long squareAndMutiply(long a,long q,long n){
		int m=0;
		long result=1;
		while(true){
			
			if((q & 0x01)==1)
				result=result*a%n;
			if(q!=0){
				q = q >> 1;
				a = (a*a)%n;
			}
			else
				break;
		}
		return result;
	}
	//扩展欧几里得算法
	static long exgcd(long a,long b,long[] arr){
		if(b == 0){
			arr[0]=1;
			arr[1]=0;
			return a;
		}
		long g = exgcd(b,a%b,arr);
		long t = arr[0];
		arr[0]=arr[1];//x1=y2
		arr[1]=t-(a/b)*arr[1];//y1=x2-[a/b]*y2
		return g;
	}

	static long rsaEn(long p,long q,long e,long m){
		String comment="";

		if(!isPrime(p)){
			while(!isPrime(++p)){};
			comment+="not a prime.auto use p=";
			comment+=p;
			comment+="\n";
		}
		if(!isPrime(q)){
			while(!isPrime(++q)){};
			comment+="not a prime.auto use q=";
			comment+=q;
			comment+="\n";		}
		long phi=(p-1)*(q-1);
		comment+="phi=";
		comment+=phi;
		comment+="\n";
		long n=p*q;
		comment+="n=";
		comment+=n;
		comment+="\n";

		long[] arr = new long[2];
		long d;
		//计算e的逆元d
		if(exgcd(e,phi,arr)==1){
			d=arr[0];
		}
		else{
			//若gcd(e,phi)≠1，则自动帮你换个e
			while(exgcd(++e,phi,arr)!=1){};
			comment+="gcd(phi,e) should be 1.auto use e=";
			comment+=e;
			comment+="\n";
			d=arr[0];
		}
		//确保d为正数
		d=(d+phi)%phi;
		comment+="d=";
		comment+=d;
		comment+="\n";
		
		//计算明文m的密文c
		long c = squareAndMutiply(m,e,n);

		System.out.println("encrypted message:");
		System.out.println(c);
		System.out.println("\n--------\n");
		System.out.println(comment);
		return c;
	}
	static long rsaDe(long p,long q,long e,long c){
		String comment="";

		if(!isPrime(p)){
			while(!isPrime(++p)){};
			comment+="not a prime.auto use p=";
			comment+=p;
			comment+="\n";
		}
		if(!isPrime(q)){
			while(!isPrime(++q)){};
			comment+="not a prime.auto use q=";
			comment+=q;
			comment+="\n";		}
		long phi=(p-1)*(q-1);
		comment+="phi=";
		comment+=phi;
		comment+="\n";
		long n=p*q;
		comment+="n=";
		comment+=n;
		comment+="\n";

		long[] arr = new long[2];
		long d;
		if(exgcd(e,phi,arr)==1){
			d=arr[0];
		}
		else{
			while(exgcd(++e,phi,arr)!=1){};
			comment+="gcd(phi,e) should be 1.auto use e=";
			comment+=e;
			comment+="\n";
			d=arr[0];
		}
		d=(d+phi)%phi;
		comment+="d=";
		comment+=d;
		comment+="\n";

		//计算密文c的明文m
		long m = squareAndMutiply(c,d,n);

		System.out.println("decrypted message:");
		System.out.println(m);
		System.out.println("\n--------\n");
		System.out.println(comment);
		return m;
	}

	public static void main(String[] args){
		
		
		Scanner sc = new Scanner(System.in);

		System.out.print("p=");
		long p=sc.nextLong();
		
		System.out.print("q=");
		long q=sc.nextLong();
		
		
		System.out.print("e=");
		long e=sc.nextLong();


		System.out.print("m=");
		long m=sc.nextLong();
		rsaEn(p,q,e,m);
		System.out.print("c=");
		long c=sc.nextLong();
		rsaDe(p,q,e,c);



	}
}
