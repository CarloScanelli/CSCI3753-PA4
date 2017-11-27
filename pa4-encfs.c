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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
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

/* Struct to hold path and key phrase */
struct encfs_state{
	char* mirror_dir;
	char* phrase;
};

/* Reference [12]: fuse-tutorial/parms.h */
#define ENCFS_DATA ((struct encfs_state *) fuse_get_context()->private_data)


/* Function to get the path to the desired directory to mirror */
static void get_path(char cpath[PATH_MAX], const char *path)
{
    strcpy(cpath, ENCFS_DATA->mirror_dir);
    strncat(cpath, path, PATH_MAX); //ridiculously long paths will break here

}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);

	int res;

	res = lstat(cpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = access(cpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);

	int res;

	res = readlink(cpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(cpath);
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
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(cpath, mode);
	else
		res = mknod(cpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{

	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = mkdir(cpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = unlink(cpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = rmdir(cpath);
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
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = chmod(cpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = lchown(cpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = truncate(cpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(cpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = open(cpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int fd;
	int res;

	(void) fi;
	fd = open(cpath, O_RDONLY);
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
	// char* cpath[PATH_MAX];
	// get_path(cpath, path);
	
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
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
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res;

	res = statvfs(cpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
    (void) fi;

    int res;
    res = creat(cpath, mode);
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
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res = lsetxattr(cpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res = lgetxattr(cpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res = llistxattr(cpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	/* Get the correct path */
	char* cpath[PATH_MAX];
	get_path(cpath, path);
	
	int res = lremovexattr(path, name);
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
	if (argc != 4){
		printf("Wrong number of arguments. Correct format is: ./pa4-encfs <Key Phrase> <Mirror Directory> <Mount Point>\n");
		return 1;
	}

	/* Define struct to hold current state */
	struct encfs_state *encfs_data;	
	encfs_data = malloc(sizeof(struct encfs_state));
	if (encfs_data == NULL){
		perror("main calloc");
		abort();
	}

	/* Get the real path and key phrase from command line argument and store them into the struct */
	encfs_data->mirror_dir = realpath(argv[argc-2], NULL);
	encfs_data->phrase = argv[1];

	return fuse_main(argc, argv, &xmp_oper, encfs_data);
}
