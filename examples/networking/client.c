#include "../libDES/libDES.h"
#include "../libsock/libsock.h"

int main(int argc, char **argv)
{
  long long unsigned int keys[] = {
    *ld_obfuscate( 0x3b3898371520f75e ),
    *ld_obfuscate( 0x09872384734743e2 ),
    *ld_obfuscate( 0xef4432847347445e ),
    *ld_obfuscate( 0x87089237549fff83 ),
    *ld_obfuscate( 0x9398478293489233 ), 
  };

  int fd = 0;
  char msg[50] = "Hello Block Cipher World!\n";
  char enc_msg[50];

  fd = _lc_connect("localhost", "5555");   /* Connect to remote */
  ld_send_iv(fd);                          /* Send rand IV to remote */
  
  memset(enc_msg, 0, sizeof enc_msg);
  ld_encryptm(msg, enc_msg, LD_NDES, 5, keys); /* Encrypt with 5DES */

  send(fd, enc_msg, sizeof enc_msg, 0);        /* Send off to remote */
  printf("\nSent: %sEncryted as: %s\n\n", msg, enc_msg);

  close(fd);
  return 0;
}
