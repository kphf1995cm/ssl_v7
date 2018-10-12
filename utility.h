/*
 * File: utility.h
 * ---------------
 * Description:
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#ifndef UTILITY_H
#define UTILITY_H

#include <stdlib.h>
#include <errno.h>

#define ERR_EXIT(m) \
	do { \
		perror(m); \
		exit(EXIT_FAILURE); \
	} while (0)

#endif
