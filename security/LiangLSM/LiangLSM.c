#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define USER2ROLE_PATH "/etc/LiangLSM/user2role"
#define ROLE2PERMISSION_PATH "/etc/LiangLSM/role2PERMISSION"
#define CONTROL_PATH "/etc/LiangLSM/control"
#define MAX_ROLENAME 20

char* permission_list[] = {
	"create file",
	"rename file"
};
#define PERMISSION_COUNT (sizeof(permission_list)/sizeof(char*))

int get_role(const int uid, char *role){
	struct file *fout = filp_open(USER2ROLE_PATH, O_RDONLY, 0);
	if(!fout || IS_ERR(fout)){
		printk("LiangLSM: load file error\n");
		return -1;
	}

	int _uid;
	int res = 0;
	while(kernel_read(fout,(char*)&uid, sizeof(int), &fout->f_pos) > 0){
		kernel_read(fout, role, sizeof(char) *(MAX_ROLENAME+1), &fout->f_pos);
		if(uid == _uid){
			printk("LiangLSM: uid: %d, role: %s\n", uid, role);
			res = 1;
			break;
		}
	}

	if(res == 0)
		printk("LiangLSM: uid: %d has no role\n", uid);
	filp_close(fout, NULL);
	return res;
}

int role_permission(const char *role, const int op){
	struct file *fout = filp_open(ROLE2PERMISSION_PATH, O_RDONLY, 0);
	if(!fout || IS_ERR(fout)){
		printk("LiangLSM: load file error\n");
		return -1;
	}

	char _role[MAX_ROLENAME+1];
	int _permission[PERMISSION_COUNT];
	int res = -1;

	while(kernel_read(fout, _role, sizeof(char) *(MAX_ROLENAME+1), &fout->f_pos) > 0){
		if(strcmp(role, _role))
			continue;

		kernel_read(fout,(char*)_permission, sizeof(int) * PERMISSION_COUNT, &fout->f_pos);	
		if(_permission[op]){
			printk("LiangLSM: role: %s has permission %s\n", role, permission_list[op]);
			res = 1;
			break;
		}
		else{
			printk("LiangLSM: role: %s has no permission %s\n", role, permission_list[op]);
			res = 0;
			break;
		}
	}

	if(res == -1)
		printk("LiangLSM: role: %s not exist", role);
	filp_close(fout, NULL);
	return res;
}

int is_enable(void){
	struct file *fout = filp_open(CONTROL_PATH, O_RDONLY, 0);
	if(!fout || IS_ERR(fout)){
		printk("LiangLSM: load file error\n");
		return -1;
	}

	int state;
	kernel_read(fout,(char*)&state, sizeof(int), &fout->f_pos);
	filp_close(fout, NULL);

	return state;
}

int user_permission(int uid, int op){
	char role[MAX_ROLENAME+1];
	if(!is_enable())
		return 0;
	if(uid <= 999)
		return 0;
	if(get_role(uid, role) != 1)
		return 0;

	if(role_permission(role, op) == 0)
		return -1;
	else{
		return 0;
	}
}

int liang_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int uid = current->real_cred->uid.val;
	printk("LiangLSM: call inode_create by uid: %d\n", uid);
	return user_permission(uid, 0);
}

int liang_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry){
	int uid = current->real_cred->uid.val;
	printk("LiangLSM: call inode_rename by uid: %d\n", uid);
	return user_permission(uid, 1);
}

static struct security_hook_list liang_hooks[] = {
    LSM_HOOK_INIT(inode_rename, liang_inode_rename),
    LSM_HOOK_INIT(inode_create, liang_inode_create),
};

void __init liang_add_hooks(void){
    pr_info("LiangLSM: becoming mindful.\n");
    security_add_hooks(liang_hooks, ARRAY_SIZE(liang_hooks), "LiangLSM");
}

static __init int liang_init(void){
    liang_add_hooks();
    return 0;
}

DEFINE_LSM(LiangLSM) = {
	.name = "LiangLSM",
	.init = liang_init,
};
