// Secure I/O and filesystem operations

#ifndef _SECUREIO_H_
#define _SECUREIO_H_

#include <sys/types.h>


#define SECUREIO_BUFSIZE 8192


// Writes absolute path pointed by descriptor fd to buffer *buf
// Returns buf if successful
// Returns NULL if error has occured
char *get_path_from_descriptor(int fd, char *buf);


// Returns 1 if subdir is subdirectory of dir, 0 otherwise
int is_subdir(const char *dir, const char *subdir);


// Opens path for reading not following symlinks and verifies that opened path is inside parent_path
// Returns:
// descriptor if successful
// -1 if path does not exist or is a symlink
// -2 if opened path is NOT inside parent_path or cannot be determined
int open_not_symlink(const char *path, const char *parent_path);


// Closes descriptor (if it is > 0)
void closefd(int fd);


// Tries to read first directory entry in order to ensure that descriptor is valid
// Returns 0 if reading succeeded or -1 if error has occured
int check_dir(int fd);


// Checks if path is a directory (in secure manner)
// Also opens path (if descriptor fd == -1) and then checks that opened path is inside parent_path
// Returns descriptor if path refers to directory
// Returns -1 if path does not exist or is not a directory
// Returns -2 if opened path is NOT inside parent_path or cannot be determined
int isdir(const char *path, int fd, const char *parent_path);


// Sets permissions to directory (in secure manner)
// Returns descriptor if successful
// Returns -1 if error has occured
// Returns -2 if opened path is NOT inside parent_path or cannot be determined
int set_perm_dir_secure(const char *path, mode_t perm, int fd, const char *parent_path);


// Sets owner and group of directory (in secure manner)
// Returns descriptor if successful
// Returns -1 if error has occured
// Returns -2 if opened path is NOT inside parent_path or cannot be determined
int set_owner_dir_secure(const char *path, uid_t uid, gid_t gid, int fd, const char *parent_path);


// Creates directory if it does not exist, sets permissions/owner otherwise
// Returns descriptor if successful
// Returns -1 if error has occured
int create_dir_secure(const char *path, mode_t perm, uid_t uid, gid_t gid, int fd, const char *parent_path);


// Recursive directory creation function
// Returns 0 if successful
// Returns -1 if error has occured
int makedirs_secure(const char *path, mode_t perm, uid_t uid, gid_t gid, const char *parent_path);


#endif
