/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */
#include "ckvs_client.h"
#include <stdio.h>
#include <stdbool.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_httpd.h"

#define MIN_ARG_NB 3

#define STATS_COMMAND "- cryptkvs [<database>|<url>] stats"
#define GET_COMMAND "- cryptkvs [<database>|<url>] get <key> <password>"
#define SET_COMMAND "- cryptkvs [<database>|<url>] set <key> <password> <filename>"
#define NEW_COMMAND "- cryptkvs [<database>|<url>] new <key> <password>"
#define HTTPD_COMMAND "- cryptkvs <database> new <key> <password>"

#define URL_PREFIXE_1 "https://"
#define URL_PREFIXE_2 "http://"

typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]) ;

typedef struct ckvs_command_mapping{
    const char* name;
    const char* usage_description;
    ckvs_command command;
    ckvs_command command_URL;
} ckvs_command_mapping_t ;

ckvs_command_mapping_t commands[] = {
    {"stats", STATS_COMMAND, ckvs_local_stats, ckvs_client_stats},
    {"get", GET_COMMAND, ckvs_local_get, ckvs_client_get},
    {"set", SET_COMMAND, ckvs_local_set, NULL},
    {"new", NEW_COMMAND, ckvs_local_new, NULL},
    {"httpd", HTTPD_COMMAND, ckvs_httpd_mainloop, NULL}
    
    
};


static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        size_t nb_commands = sizeof(commands)/sizeof(ckvs_command_mapping_t);
        pps_printf("Available commands:\n");
        for (size_t i = 0; i < nb_commands; i++)
        {
            pps_printf("%s\n",commands[i].usage_description);
        }
        
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}



/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 * @return int error code 
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{    
    if (argc < MIN_ARG_NB) return ERR_INVALID_COMMAND;
    

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    size_t function_index = 0;
    size_t nb_commands = sizeof(commands)/sizeof(ckvs_command_mapping_t);
    bool is_URL= false;
    is_URL = (strncmp(db_filename,URL_PREFIXE_1,8) == 0) ? true : false;
    is_URL = (strncmp(db_filename,URL_PREFIXE_2,7) == 0 || is_URL== true) ? true : false;

    while(function_index < nb_commands){
        ckvs_command_mapping_t potential_cmd = commands[function_index];
        if(strcmp(potential_cmd.name, cmd) == 0){
            int optargc = argc - 3;
            char** optargv = argv + 3;

            return  (is_URL ? potential_cmd.command_URL(db_filename, optargc, optargv) :  
                              potential_cmd.command(db_filename, optargc, optargv) );
        }
        function_index++;
    }
    
    return ERR_INVALID_COMMAND;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */


int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}

#endif
