#include <stdio.h>
#include <stdlib.h>

int main(){
	char *text = "ffff";
	
	FILE *fptr;
	//fptr = fopen("/sys/kernel/debug/reutos/write_output", "w");
	fptr = fopen("/sys/kernel/debug/reutos/exit_module", "w");
	if(fptr == NULL){
		printf("Error!!, (%d)\n", (int) fptr);
		return -1;
	}
	char buff[1000];
	//int ret = fprintf(fptr, "ffff");
	int ret = fprintf(fptr, "1");
	//int ret = fgets(buff, 1000, fptr);
	printf("Ret: %d\n", ret);
	printf("Read contents of buf: %s\n", buff); 
	fclose(fptr);
	return 0;
}
