#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define USER2ROLE_PATH "/etc/LiangLSM/user2role"
#define ROLE2PERMISSION_PATH "/etc/LiangLSM/role2permission"
#define CONTROL_PATH "/etc/LiangLSM/control"
#define MAX_ROLENAME 20

char* permission_list[] = {
	"create directory",
	"delete directory",
	"alloc task",
	"create socket",
};
#define PERMISSION_COUNT (sizeof(permission_list)/sizeof(char*))

int write_user2role(int uid, char *role){
	FILE *fp = fopen(USER2ROLE_PATH, "ab");
	if(!fp){
		printf("file open failed (%s)\n", USER2ROLE_PATH);
		return -1;
	}
	
	fwrite(&uid, sizeof(int), 1, fp);
	fwrite(role, sizeof(char), MAX_ROLENAME+1, fp);
	
	fclose(fp);
	return 1;
}

int user_exists(int uid){
	FILE *fp = fopen(USER2ROLE_PATH, "rb");
	if(!fp){
		return 0;
	}
	
	int _uid;
	while(fread(&_uid, sizeof(int), 1, fp)){
		if(_uid == uid){
			fclose(fp);
			return 1;
		}
		fseek(fp, sizeof(char) *(MAX_ROLENAME + 1), SEEK_CUR);
	}
	fclose(fp);
	return 0;
}

int add_user2role(int uid, char *role){
	int role_len = strlen(role);
	if(role_len > MAX_ROLENAME){
		printf("Role name is too long\n");
		return -1;
	}
	if(user_exists(uid) == 1){
		printf("The role of the user already exists\n");
		return -1;
	}
	
	char _role[MAX_ROLENAME+1];
	for(int i = 0; i < MAX_ROLENAME; i++){
		if(i < role_len)
			_role[i] = role[i];
		else
			_role[i] = '\0';
	}
	
	return write_user2role(uid, _role);
}

int del_user2role(int uid){
	FILE *fp = fopen(USER2ROLE_PATH, "rb");
	if(!fp){
		printf("open file failed (%s)\n", USER2ROLE_PATH);
		return -1;
	}

	int _uid[100];
	char _role[100][MAX_ROLENAME+1];
	int index = 0;

	while(fread((char*)&_uid[index], sizeof(int), 1, fp)){
		fread(_role[index], sizeof(char), MAX_ROLENAME+1, fp);

		if(_uid[index] != uid){
			index++;
		}
	}
	fclose(fp);

	fp = fopen(USER2ROLE_PATH, "wb");
	for(int i = 0; i < index; i++){
		fwrite((char*)&_uid[i], sizeof(int), 1, fp);
		fwrite(_role[i], sizeof(char), MAX_ROLENAME+1, fp);
	}

	fclose(fp);
	return 1;
}

int change_user2role(int uid, char *role){
	if(del_user2role(uid) == 1)
		return add_user2role(uid, role);
	else
		return -1;
}

int show_user2role(){
	FILE *fp = fopen(USER2ROLE_PATH, "rb");
	if(!fp){
		printf("No items now\n");
		return -1;
	}

	int uid;
	char role[MAX_ROLENAME+1];
	while(fread((char*)&uid, sizeof(int), 1, fp)){
		fread(role, sizeof(char), MAX_ROLENAME+1, fp);
		printf("uid %d : %s\n", uid, role);
	}
	
	fclose(fp);
	return 1;
}


int write_role(char *role, int *permission){
	FILE *fp = fopen(ROLE2PERMISSION_PATH, "ab");	
	if(!fp){
		printf("file open failed (%s)\n", ROLE2PERMISSION_PATH);
		return -1;
	}
	
	fwrite(role, sizeof(char), MAX_ROLENAME+1, fp);
	fwrite(permission, sizeof(int), PERMISSION_COUNT, fp);
	fclose(fp);
	return 1;
}

int role_exists(char *role){
	FILE *fp = fopen(ROLE2PERMISSION_PATH, "rb");
	if(!fp){
		return 0;
	}
	
	char _role[MAX_ROLENAME+1];
	while(fread(_role, sizeof(char), MAX_ROLENAME+1, fp)){
		if(!strcmp(_role, role)){
			fclose(fp);
			return 1;
		}
		fseek(fp, sizeof(int) * PERMISSION_COUNT, SEEK_CUR);
	}
	
	fclose(fp);
	return 0;
}

int add_role(char *role, int *permission){
	int role_len = strlen(role);
	
	if(role_len > MAX_ROLENAME){
		printf("Role name is too long\n");
		return -1;
	}
	if(role_exists(role) == 1){
		printf("Role already exists\n");
		return -1;
	}
			
	char _role[MAX_ROLENAME+1];
	for(int i = 0; i < MAX_ROLENAME; i++)
	{
		if(i < role_len)
			_role[i] = role[i];
		else
			_role[i] = '\0';
	}
	
	return write_role(_role, permission);
}

int del_role(char *role){
	FILE *fp = fopen(ROLE2PERMISSION_PATH, "rb");
	if(!fp){
		printf("open file failed (%s)\n", ROLE2PERMISSION_PATH);
		return -1;
	}
	
	char _role[100][MAX_ROLENAME+1];
	int _permission[100][PERMISSION_COUNT];
	int index= 0;

	while(fread(_role[index], sizeof(char), MAX_ROLENAME+1, fp))
	{
		fread(_permission[index], sizeof(int), PERMISSION_COUNT, fp);

		if(strcmp(_role[index], role)){
			index++;		
		}
	}
	fclose(fp);

	fp = fopen(ROLE2PERMISSION_PATH, "wb");
	for(int i =0; i < index; i++){
		fwrite(_role[i], sizeof(char), MAX_ROLENAME+1, fp);
		fwrite(_permission[i], sizeof(int), PERMISSION_COUNT, fp);
	}

	fclose(fp);
	return 1;
}

int change_role(char *role, int *permission){
	if(del_role(role) == 1)
		return add_role(role, permission);
	else
		return -1;
}

int show_roles(){
	FILE *fp = fopen(ROLE2PERMISSION_PATH, "rb");
	if(!fp){
		printf("No items now\n");
		return -1;
	}

	int permission[PERMISSION_COUNT];
	char role[MAX_ROLENAME+1];
	while(fread(role, sizeof(char), MAX_ROLENAME+1, fp)){
		printf("%s permission:\n", role);
		fread(permission, sizeof(int), PERMISSION_COUNT, fp);
		for(int i = 0; i < PERMISSION_COUNT; i++){
			printf("%s: %s\n", permission_list[i], permission[i] ? "yes" : "no");
		}
		printf("\n");
	}
	
	fclose(fp);
	return 1;
}

int get_state(){
	FILE *fp = fopen(CONTROL_PATH, "rb");
	if(!fp){
		printf("file open failed (%s)\n", CONTROL_PATH);
		return -1;
	}

	int state;
	fread((char*)&state, sizeof(int), 1, fp);
	fclose(fp);
	
	return state;
}

int set_state(int state){
	FILE *fp = fopen(CONTROL_PATH, "wb");
	if(!fp){
		printf("file open failed (%s)\n", CONTROL_PATH);
		return -1;
	}

	fwrite((char*)&state, sizeof(int), 1, fp);
	fclose(fp);

	return 1;
}

int main(int argc, char *argv[]){
	if(argc == 1){
		printf("Error: too few arguments\n");
		return -1;
	}
		
	if(!strcmp(argv[1], "-s")){
		if(argc < 3){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 3){
			printf("Error: too many arguments\n");
			return -1;
		}
			
		if(!strcmp(argv[2], "user2role")){
			show_user2role();
			return 0;
		}
		else if(!strcmp(argv[2], "roles")){
			show_roles();
			return 0;
		}
		else{
			printf("Error: invalid argument\n");
			return -1;
		}
	}
	else if(!strcmp(argv[1], "-ra")){
		if(argc < 4){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 4){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		if(strlen(argv[3]) != PERMISSION_COUNT){
			printf("Error: invalid permission setting\n");
			return -1;
		}

		int permission[PERMISSION_COUNT];
		for(int i = 0; i < PERMISSION_COUNT; i++){
			permission[i] = argv[3][i] - '0';
			if(permission[i] != 0 && permission[i] != 1){
				printf("Error: invalid permission setting\n");
				return 0;
			}
		}
		
		if(add_role(argv[2], permission) == 1)
			printf("Succeed to add role\n");
		else
			printf("Fail to add role\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-ua")){
		if(argc < 4){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 4){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		int uid = atoi(argv[2]);
		if(add_user2role(uid, argv[3]) == 1)
			printf("Succeed to add the role of the user\n");
		else
			printf("Fail to add the role of the user\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-rd")){
		if(argc < 3){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 3){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		if(del_role(argv[2]) == 1)
			printf("Succeed to delete role\n");
		else
			printf("Fail to adeletedd role\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-ud")){
		if(argc < 3){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 3){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		int uid = atoi(argv[2]);
		if(del_user2role(uid) == 1)
			printf("Succeed to delete the role of the user\n");
		else
			printf("Fail to delete the role of the user\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-rc")){
		if(argc < 4){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 4){
			printf("Error: too many arguments\n");
			return -1;
		}

		if(strlen(argv[3]) != PERMISSION_COUNT){
			printf("Error: invalid permission setting\n");
			return 0;
		}

		int permission[PERMISSION_COUNT];
		for(int i = 0; i < PERMISSION_COUNT; i++){
			permission[i] = argv[3][i] - '0';
			if(permission[i] != 0 && permission[i] != 1){
				printf("Error: invalid permission setting\n");
				return 0;
			}
		}
		
		if(change_role(argv[2], permission) == 1)
			printf("Succeed to change role\n");
		else
			printf("Fail to change role\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-uc")){
		if(argc < 4){
			printf("Error: too few arguments\n");
			return -1;
		}
		if(argc > 4){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		int uid = atoi(argv[2]);
		if(change_user2role(uid, argv[3]) == 1)
			printf("Succeed to change the role of the user\n");
		else
			printf("Fail to change the role of the user\n");
		
		return 0;
	}
	else if(!strcmp(argv[1], "-state")){
		if(argc > 2){
			printf("Error: too many arguments\n");
			return -1;
		}
		
		int state = get_state();
		if(state == 1)
			printf("State: Enabled\n");
		else if(state == 0)
			printf("State: Disabled\n");

		return 0;
	}
	else if(!strcmp(argv[1], "-enable")){
		if(argc > 2){
			printf("Error: too many arguments\n");
			return -1;
		}

		if(set_state(1) == 1)
			printf("Enabled\n");

		return 0;
	}
	else if(!strcmp(argv[1], "-disable")){
		if(argc > 2){
			printf("Error: too many arguments\n");
			return -1;
		}

		if(set_state(0) == 1)
			printf("Disabled\n");

		return 0;
	}
	else{
		printf("Error: invalid argument\n");
		return -1;
	}
}
