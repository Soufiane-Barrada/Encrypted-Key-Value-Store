/**
 * @file ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 *
 */

#pragma once


/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_stats(const char* filename, int optargc, char* optargv[]);

/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_get(const char* filename, int optargc, char* optargv[]);


/**
 * @brief Opens the CKVS database at the given filename and executes the 'set' command,
 * ie. fetches the entry corresponding to the key and password and
 * then sets the encrypted content of valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_set(const char* filename, int optargc, char* optargv[]);


/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_new(const char* filename, int optargc, char* optargv[]);


