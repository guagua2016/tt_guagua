#ifndef _FILE_UTIL_H_
#define _FILE_UTIL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

class CFileUtil {
public:
	static bool mkdirs(char *path);
	static bool isDirectory(const char *path);
	static bool isSymLink(const char *paht);
	static bool exist(const char *path);
};


#endif /* _FILE_UTIL_H_ */
