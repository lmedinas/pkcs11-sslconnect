#include "common.h"
#include <openssl/err.h>
#include <openssl/engine.h>

BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num,
  int rwflag,void *userdata);
static void sigpipe_handle(int x);

/* A simple error and exit routine*/
int err_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(string)
  char *string;
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

static void sigpipe_handle(int x){
}

SSL_CTX *initialize_ctx(keyfile)
  char *keyfile;
  {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

//////////////PKCS111 ENGINE///////////////

    struct {
	const char * slot_id;
	X509 * cert;
    } parms = {"4500000000000000",NULL};

    //X509 * m_cert;
    EVP_PKEY *m_pkey;

    ENGINE *engine;

    ENGINE_load_builtin_engines();
    
    engine = ENGINE_by_id("dynamic");
    ENGINE_ctrl_cmd_string(engine,"SO_PATH", "/usr/lib/engines/engine_pkcs11.so" ,0);
    ENGINE_ctrl_cmd_string(engine,"ID","pkcs11",0);
    ENGINE_ctrl_cmd_string(engine,"LIST_ADD","1",0);
    ENGINE_ctrl_cmd_string(engine,"LOAD",NULL,0);
    ENGINE_ctrl_cmd_string(engine,"VERBOSE",0,0);
    ENGINE_ctrl_cmd_string(engine,"MODULE_PATH", "/usr/local/lib/libbeidpkcs11.so",0);
    ENGINE_init(engine);


    ENGINE_ctrl_cmd(engine, "LOAD_CERT_CTRL", 0, &parms, NULL, 1);

    X509 *m_cert1 = parms.cert;

    if (!(m_pkey = ENGINE_load_private_key(engine,parms.slot_id, NULL, NULL)))
	berr_exit("Error loading private key. Do you have a card ?");

///////////////////////////////////////////


    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);
    
    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates from a file*/
    /*if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");*/
    
    /*load our certificates from the card*/
    if(!(SSL_CTX_use_certificate(ctx,m_cert1)))
	berr_exit("Can't read certificate file");
    
    /*load our private keys from the card*/
    if(!(SSL_CTX_use_RSAPrivateKey(ctx, EVP_PKEY_get1_RSA(m_pkey))))
	berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      CA_LIST, "/etc/ssl/certs")))
      berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    
    return ctx;
  }
     
void destroy_ctx(ctx)
  SSL_CTX *ctx;
  {
    SSL_CTX_free(ctx);
  }
