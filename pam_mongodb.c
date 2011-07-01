/**************************************************
 PAM_MongoDB Module

 Authenticates users from PAM module, via MongoDB  server.
 This connects to a MongoDB server, calls DB authentication 
 function, and if it succeeds, the user is authenticated.

 It is advisable to have users authenticate to a  read-only
 database.  This program will not make any checks, but for
 security purposes, this is suggested.

 To compile:

 Run the included "build" script.

 This requires both libmongo-client and glib libraries and
 headers to be installed.

 libmongo-client:
 https://github.com/algernon/libmongo-client

 glib should be installable from your package manager.

 Possible options for module:
 - server=<ip/host>: The IP or hostname to connect to.
 - port=<#>: The port the MongoDB server listens on.
 - db=<database>: Database to connect to.

 This module is free to use for any purpose.  The  only
 restriction is that I request you  notify me (eric@zorveo.com)
 if you use this.  I developed this for a learning experience, and nothing more.
 **************************************************/
/** Per PAM module specifications, these must be included. **/
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/** For C-functions that are needed. **/
#include <stdio.h>
#include <stdlib.h>

/** For MongoDB stuff. **/
#include <bson.h>
#include <mongo.h>

/** Used for LOGIN_NAME_MAX define **/
#include <bits/local_lim.h>

/** Used to handle errno in error blocks **/
#include <errno.h>

/** Just a sanity check **/
#ifndef PAM_EXTERN
	#ifdef PAM_STATIC
		#define PAM_EXTERN static
	#else
		#define PAM_EXTERN extern
	#endif
#endif

/** Prints strings to screen, use in same fashion as printf()
    Not used except for when personally debugging code. **/
#define D(x) do {									\
			printf("[%s:%s(%d)] ", __FILE__, __FUNCTION__, __LINE__);	\
			printf x;							\
			printf("\n");							\
		} while (0)

/**
 * struct options
 * Various options configured inside of PAM config files (i.e.: /etc/pam.d/sshd)
 * See README on how to configure options.
 **/
struct options {
	char *server;	// The server to connect to
	char *db;	// The database to authenticate to
	int port;	// The port "server" is listening on
	int ask_all;	// When enabled, will ask user for the server, db and port
};

/**
 * parse_options()
 * argc - Number of arguments to parse          [in]
 * argv - Arguments to check (" " deliminated)  [in]
 * opts - Pointer to struct options{}           [out]
 *
 * Parses arguments passed from PAM to the module itself.
 **/
static void parse_options(int argc, const char **argv, struct options *opts){
	// Set default options (server & db SHOULD be changed)
	opts->server  = "127.0.0.1";
	opts->db      = "test";
	opts->port    = 27017;
	opts->ask_all = 0;

	int i = 0;

	/**
	 * for() loop to get various arguments.  See struct options{} for details.
	 **/
	for(; i < argc; i++){
		if(!strcmp(argv[i], "askall"))
			opts->ask_all = 1;
		if(!strncmp(argv[i], "server=", 7))
			opts->server = (char*)argv[i] + 7;
		if(!strncmp(argv[i], "db=", 3))
			opts->db = (char*)argv[i] + 3;
		if(!strncmp(argv[i], "port=", 5))
			opts->port = atoi(argv[i] + 5);
	}
}

/**
 * pam_sm_authenticate()
 * pamh  - Handle to PAM structure/interface 					[in]
 * flags - Special settings for PAM (PAM_SILENT or PAM_DISALLKOW_NULL_AUTHTOK) 	[in]
 * argc	 - Number of arguments that are being passed to the module		[in]
 * argv	 - Arguments that have been passed to module				[in]
 *
 * Handler function for PAM.  This is needed for authentication to happen.
 **/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
				   int          flags,
                                   int           argc,
                                   const char *argv[]){
	struct pam_conv *conv;			// Ability to prompt user for information or display text
	struct pam_message msg[5], *msgp;	// Structure for pam_conv{} (holds values for prompts)
	struct pam_response *resp;		// Contains the user's response of conv

	// Holds username of current user (why pam_get_user() asks for a const char, I don't know...)
	const char *user;

	// Holder values for both db_user and db_pass (LOGIN_NAME_MAX is generally 256)
	char db_user[LOGIN_NAME_MAX] = {'\0'};
	char db_pass[LOGIN_NAME_MAX] = {'\0'};

	// Stores data for both prompts and user's answers (see below)
	char *answer, *prompt[5];

	// Holder for return values of PAM functions (defaults to PAM_SUCCESS if nothing changes)
	int pam_err = PAM_SUCCESS;

	// Useful struct for options
	struct options opts;

	// Actually parses all of the options we were given
	parse_options(argc, argv, &opts);

	// Used for MongoDB connection
	mongo_sync_connection *conn;

	// Holds errno value so it doesn't get erased
	int e;

	// Since mongo-client uses glib, we have to use some glib-typecast variables
	gchar *error = NULL;

	// Set up PAM to allow us to use conversation items
	pam_err = pam_get_item(pamh, PAM_CONV, (const void**)&conv);

	// Failed to get items
	if(pam_err != PAM_SUCCESS)
		return PAM_SYSTEM_ERR;

	// Get username that's trying to authenticate
	pam_err = pam_get_user(pamh, &user, NULL);

	// Unable to do this, so we have to return failure
	if(pam_err != PAM_SUCCESS){
		printf("Unable to get login name: %s", pam_strerror(pamh, pam_err));
		return PAM_AUTH_ERR;
	}

	// Set up prompts to ask the user
	prompt[0] = (char*)strdup("Username (leave blank for log in name): ");
	prompt[1] = (char*)strdup("Password: ");
	prompt[2] = (char*)strdup("Server Host or IP: ");
	prompt[3] = (char*)strdup("Port number: ");
	prompt[4] = (char*)strdup("Database: ");

	/**
	 * msg_style:
	 * Sets display of user's text while inputting.
	 * PAM_PROMPT_ECHO_ON  - Display what the user types (less secure)
	 * PAM_PROMPT_ECHO_OFF - Don't dispaly what the user types (more secure)
	 *
	 * For msg[2] - msg[4], if you want it to be more secretive/secure, then
	 * change the msg_style.  I did this just because I can.
	 **/
	msg[0].msg_style = PAM_PROMPT_ECHO_ON;
	msg[0].msg = prompt[0];
	msg[1].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[1].msg = prompt[1];
	msg[2].msg_style = PAM_PROMPT_ECHO_ON;
	msg[2].msg = prompt[2];
	msg[3].msg_style = PAM_PROMPT_ECHO_ON;
	msg[3].msg = prompt[3];
	msg[4].msg_style = PAM_PROMPT_ECHO_ON;
	msg[4].msg = prompt[4];

	// If user is to answer all fields, prompt for all, otherwise just ask for username & password
	int end = (opts.ask_all == 1) ? 5 : 2;
	int cred = 0;

	for(; cred < end; cred++){
		// Get a pointer to the current message to ask the user
		msgp = &msg[cred];

		// Sanity check to make sure no response is carried over
		resp = NULL;

		// Ask the user (&msg), getting the input (&resp)...argument 1 cannot be more than 1
		pam_err = (*conv->conv)(1,(const struct pam_message**)&msgp,&resp,conv->appdata_ptr);

		// Nothing went wrong!
		if(pam_err == PAM_SUCCESS){
			// Store the user's response into a buffer
			answer = resp->resp;

			// We don't want something longer than our buffers can hold
			if(strlen(answer) > LOGIN_NAME_MAX){
				pam_err = PAM_SERVICE_ERR;
				break;
			}

			// If no answer was given AND we already asked for the username, error out
			if(!answer && (cred != 0)){
				pam_err = PAM_AUTH_ERR;
				break;
			}

			// If asked for username...
			if(cred == 0){
				// ...and no response, make it logged in user, otherwise use the given name
				if(!answer)
					sprintf(db_user, "%s", user);
				else
					sprintf(db_user, "%s", answer);
			} else{
				if(cred == 1)
					sprintf(db_pass, "%s", answer);
				else if(cred == 2)
					sprintf(opts.server, "%s", answer);
				else if(cred == 3)
					opts.port = atoi(answer);
				else if(cred == 4)
					sprintf(opts.db, "%s", answer);
			}
		}
	}

	if(pam_err != PAM_SUCCESS){
		printf("Issue making a conversation.\n");
		return PAM_SYSTEM_ERR;
	}

	// Connect to MongoDB server
	conn = mongo_sync_connect((gchar*)opts.server, opts.port, 0);

	// In the event an issue happens, store the errno into buffer e
	e = errno;

	if(!conn){
		printf("Unable to connect to mongoDB server (%d).\n", e);

		// Should this be PAM_SYSTEM_ERR instead?  It's really neither but...yeah
		return PAM_AUTH_ERR;
	}

	// No issues so far, time to authenticate
	if(pam_err == PAM_SUCCESS){
		// Another glib typecast...have to typecast db, user & pass due to (gchar*) != (char*)
		gboolean auth = mongo_sync_cmd_authenticate(conn, (gchar*)opts.db, (gchar*)db_user, (gchar*)db_pass);

		int errn = errno;

		// Authentication failed (usually a connectivity issue)
		if(!auth){
			gchar *err = NULL;

			// Get the last error, and store it into err
			mongo_sync_cmd_get_last_error(conn, opts.db, &err);

			// Tell the user the message (errn tends to more specific surprisingly)
			printf("Unable to authenticate with mongoDB %d (%s).\n", errn, err);

			// Free up allocation space
			g_free(err);

			// We failed to authenticate
			pam_err = PAM_AUTH_ERR;
		} else
			printf("Successful authentication.\n");
	}

	// Use this to free up any space left by the conversation
	if(resp){
		if(resp > resp)
			free(resp->resp);

		free(resp);
	}

	// Must be called to close the socket to the server.
	mongo_sync_disconnect(conn);

	return pam_err;
}

/**
 * Rest of pam_sm_* functions are just place holders for possible future options/implementations.
 * Please ignore for now.
 **/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
			      int          flags,
                              int           argc,
                              const char *argv[]){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
				int	     flags,
				int	      argc,
				const char *argv[]){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
				   int		flags,
				   int		 argc,
				   const char *argv[]){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
				    int		 flags,
				    int		  argc,
				    const char *argv[]){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,
				int	     flags,
				int	      argc,
				const char *argv[]){
	return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC

struct pam_module _pam_demo_modstruct = {
	"pam_demo",
	"pam_sm_authenticate",
	"pam_sm_setcred",
	"pam_sm_acct_mgmt",
	"pam_sm_open_session",
	"pam_sm_close_session",
	"pam_sm_chauthtok"
};

#endif
