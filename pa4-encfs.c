/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define PATH_MAX 4096
#define ENCRYPT 1
#define DECRYPT 0

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

/* Add namespace defintion for older kernels. Normally included in linux/xattr.h */
#ifndef XATTR_USER_PREFIX
#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN (sizeof (XATTR_USER_PREFIX) - 1)
#define XATTR_NAME "pa4-encfs.encrypted"
#define XATTR_TRUEFLAG "true"
#define XATTR_FALSEFLAG "false"
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#include <stdlib.h>
#include "aes-crypt.h"
#endif

/* Struct to hold path and key phrase, used by FUSE to communicate between user and kernel space */
struct encfs_state{
	char* mirror_dir;
	char* phrase;
};

/* Reference [12]: fuse-tutorial/parms.h */
#define ENCFS_DATA ((struct encfs_state *) fuse_get_context()->private_data)


/* Function to get the path to the desired directory to mirror */
static void get_path(char* fpath[PATH_MAX], const char *path)
{
    strcpy((char*)fpath, ENCFS_DATA->mirror_dir);
    strncat((char*)fpath, path, PATH_MAX); //paths that are too long will break here
}

/* 3a: Add support for encryption */
int encfs_encrypt(char file[], char* fpath)
{
	FILE* inFile = NULL;
	FILE* outFile = NULL;
	/* Open Files */
	inFile = fopen(file, "rb");
	if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(fpath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, ENCRYPT, ENCFS_DATA->phrase)){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
	perror("inFile fclose error\n");
    }

    return 0;
}

/* 3b: Add support for decryption */
int encfs_decrypt(char file[], char* fpath)
{
	FILE* inFile = NULL;
	FILE* outFile = NULL;
	/* Open Files */
	inFile = fopen(fpath, "rb");
	if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(file, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, DECRYPT, ENCFS_DATA->phrase)){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
	perror("inFile fclose error\n");
    }

    return 0;
}

/* Similar to xattr.util.c */
static void encfs_setxattr(char* fpath)
{
	char* tmpstr = NULL;

	/* Need to append 'user.' prefix' before attribute name */
	tmpstr = malloc(strlen(XATTR_NAME) + XATTR_USER_PREFIX_LEN + 1);
	if(!tmpstr){
	    perror("malloc of 'tmpstr' error");
	    exit(EXIT_FAILURE);
	}
	strcpy(tmpstr, XATTR_USER_PREFIX);
	strcat(tmpstr, XATTR_NAME);
	/* Set attribute */
	if(setxattr(fpath, tmpstr, XATTR_TRUEFLAG, strlen(XATTR_TRUEFLAG), 0)){
	    perror("setxattr error");
	    fprintf(stderr, "path  = %s\n", fpath);
	    fprintf(stderr, "name  = %s\n", tmpstr);
	    fprintf(stderr, "value = %s\n", XATTR_TRUEFLAG);
	    fprintf(stderr, "size  = %zd\n", strlen(XATTR_TRUEFLAG));
	    exit(EXIT_FAILURE);
	}
	/* Cleanup */
	free(tmpstr);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);

	int res;

	res = lstat((char*)fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = access((char*)fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);

	int res;

	res = readlink((char*)fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir((char*)fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo((char*)fpath, mode);
	else
		res = mknod((char*)fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{

	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = mkdir((char*)fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = unlink((char*)fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = rmdir((char*)fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = chmod((char*)fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = lchown((char*)fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = truncate((char*)fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes((char*)fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = open((char*)fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int fd;
	int res;

	(void) fi;
	fd = open((char*)fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	/* Get the correct path */
	// char* fpath[PATH_MAX];
	// get_path(fpath, path);
	
	int fd;
	int res;

	(void) fi;
	fd = open((char*)path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res;

	res = statvfs((char*)fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
    (void) fi;

    int res;
    res = creat((char*)fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res = lsetxattr((char*)fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res = lgetxattr((char*)fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res = llistxattr((char*)fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	/* Get the correct path */
	char* fpath[PATH_MAX];
	get_path(fpath, path);
	
	int res = lremovexattr((char*)path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

// Need to add an additional argument to specify which directory to mirror
int main(int argc, char *argv[])
{
	umask(0);

	/* Check number of arguments */
	if(argc < 4 || (argv[argc-2][0] == '-') || argv[argc-1][0] == '-'){
	    fprintf(stderr, "usage: %s %s\n", argv[0],
		    "<Key Phrase> <Mirror Directory> <Mount Point>");
	    exit(EXIT_FAILURE);
	}

	/* Define struct to hold current state */
	struct encfs_state *encfs_data;	
	encfs_data = malloc(sizeof(struct encfs_state));
	if (encfs_data == NULL){
		perror("main calloc");
		abort();
	}

	/* Get the correct path and key phrase from command line argument and store them into the struct */
	encfs_data->mirror_dir = realpath(argv[2], NULL);
	encfs_data->phrase = argv[1];

	/* Adjust argvs and set new argc to argc - 2 (for FUSE, which only needs the mount point) */
	/* -d comes after the mount point */
	argv[1] = argv[argc-1];
	argv[argc-1] = NULL;
	argv[argc-2] = NULL;
	argc -= 2;

	return fuse_main(argc, argv, &xmp_oper, encfs_data);
}
