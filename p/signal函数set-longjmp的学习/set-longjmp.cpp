#include<stdio.h>
#include<setjmp.h>
#include<stdlib.h> 
int main()
{
	jmp_buf env;
	int i,n,a;
	scanf("%d",&n);
	a=9; 
	i=setjmp(env);
	if(i<=n)
	{
		printf("%d %d\n",i,a);
		a++;
		longjmp(env,++i);
	}
	return 0; 
}
