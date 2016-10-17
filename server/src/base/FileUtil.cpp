#include "FileUtil.h"

#ifndef S_IRWXUGO
#define S_IRWXUGO	(S_IRWXU | S_IRWXG | S_IRWXO)
#endif

bool CFileUtil::mkdirs(char *path)
{
	struct stat stats;

	if (path == NULL)
		return false;

	if (lstat(path, &stats) == 0 && S_ISDIR(stats.st_mode))
		return true;

	mode_t umask_value = umask(0);
	umask(umask_value);
	mode_t mode = (S_IRWXUGO & (~umask_value)) | S_IWUSR | S_IXUSR;

	char *slash = path;
	while (*slash == '/') slash++;

	while (true) {
		slash = strchr(slash, '/');
		if (slash == NULL) {
			break;
		}
		*slash = '\0';
		int ret = mkdir(path, mode);
		*slash++ = '/';
		if (ret && errno != EEXIST) {
			return false;
		}

		while (*slash == '/') slash++;
	}

	if (mkdir(path, mode)) {
		return false;
	} else {
		return true;
	}
}

bool CFileUtil::isDirectory(const char *path)
{
	if (path == NULL)
		return false;

	struct stat stats;
	if (lstat(path, &stats) == 0 && S_ISDIR(stats.st_mode)) {
		return true;
	} else {
		return false;
	}
}

bool CFileUtil::isSymLink(const char *path)
{
	if (path == NULL)
		return false;

	struct stat stats;
	if (lstat(path, &stats) == 0 && S_ISLNK(stats.st_mode)) {
		return true;
	} else {
		return false;
	}
}

bool CFileUtil::exist(const char *path)
{
	if (path == NULL)
		return false;

	struct stat stats;
	if (lstat(path, &stats) == 0 && S_ISREG(stats.st_mode)) {
		return true;
	} else {
		return false;
	}
}
