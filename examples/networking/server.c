#include "../libDES/libDES.h"
#include "../libsock/libsock.h"

int main(int argc, char **argv)
{
  int listen_fd, new_fd, fd;
  char secret_msg[50], *cipher_msg;

  long long unsigned int keys[] = {
    *ld_obfuscate( 0x3b3898371520f75e ),
    *ld_obfuscate( 0x09872384734743e2 ),
    *ld_obfuscate( 0xef4432847347445e ),
    *ld_obfuscate( 0x87089237549fff83 ),
    *ld_obfuscate( 0x9398478293489233 ),
  };

  _lc_prep_select();
  _lc_max_fd = listen_fd = _lc_bind_to_port( "localhost", "5555" );
  printf("Waiting... for connections.\n");

  while (1) {
    _lc_readable_fds = _lc_master_fds;
    lc_select();

    for (fd = 0; fd <= _lc_max_fd; fd++) {
      int nbytes;
      char buf[50];

      if ( FD_ISSET(fd, &_lc_readable_fds) ) {
	if (fd == listen_fd) {
	  new_fd = lc_accept(listen_fd);
	  printf("Got connection %d, waiting for secret message\n", 
		 new_fd);

	  ld_recv_iv(new_fd);
	}
	else {
	  memset(buf, 0, sizeof buf);
	  
	  if ( (nbytes = recv(fd, buf, sizeof buf, 0)) <= 0) {
	    if (nbytes == 0) {
	      printf("socket %d hung up\n", fd);
	    }
	    else{
	      perror("recv");
	    }

	    close(fd);
	    FD_CLR(fd, &_lc_master_fds);
	  }
	  else {
	    memset(secret_msg, 0, sizeof secret_msg);	    
	    ld_decryptm(buf, secret_msg, LD_NDES, 5, keys);

	    printf("\nEncrypted message recieved: %s\nSecret "\
		   "Decrypted Message is: %s\n\n", buf, secret_msg);
	  }
	}
      }
    }
  }
  
  return 0;
}
