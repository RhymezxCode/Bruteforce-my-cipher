#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

//=========================================================
//========= Function to handle Errors
//=========================================================
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

//================================================================
//===This function receives a plaintext and its length, a key and 
//===IV and returns the encryption of the plaintext using AES-128-CBC
//===in ciphertext and the length of the ciphertext as a return value
//================================================================

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. Here we use AES 128 CBC mode*/
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
     EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

//================================================================
//===This function receives a cipherttext and its length, a key and 
//===IV and returns the decryption of the ciphertext using AES-128-CBC
//===in plaintext the length of the plaintext as a return value 
//================================================================
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. Here we use AES 128 CBC mode */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
     EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

//=========================================================
//========= Function to print a string in hexadecimal
//=========================================================
void print_hex (const unsigned char *s, int len)
{
  for(int i=0; i< len; i++)
    printf("%02x", (unsigned int) s[i]);
  printf("\n");
}

//=========================================================
//========= The Main function
//=========================================================
int main(int argc, char *argv[])
{
 
char word[16];   
FILE *fp;
fp  = fopen ("WordList.txt", "r");
if (fp != NULL) 
{
while (fscanf(fp, "%s", word) != EOF) 
    { 
      system("clear");


  /* The Key as a 16-char string  */
  unsigned char* key;

  if(strlen(word) < 16){
    int wordL;
    wordL = strlen(word);
    while(wordL < 16){
    word[wordL] = '*';
    wordL++;
    }
    word[wordL]='\0';
    printf("\nKey is: %s\n\n\n\n", word);
    key = (unsigned char*)word;
  }

  /* The IV stated in hexadecimal */
  //ffeeddccbbaa00112233445566778899")
  unsigned char iv[] ={0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};

  const char* original_plaintext = "Welcome to UWE";
  
  /* The Plaintext */
  unsigned char* plaintext = (unsigned char*)original_plaintext;

  unsigned char ciphertext[128];

  unsigned char ciphertextGiven[128] = "05e620629887d1cbb6a400a6a01b22fa";

  unsigned char decryptedtext[128];
 
  int ciphertext_len, decryptedtext_len;

  /* Encrypt the plaintext */

  ciphertext_len = encrypt (plaintext, strlen((char *)plaintext), key, iv,ciphertext);

  /* Print the cipher text as hexa */
  BIO_dump_fp (stdout, (const char*)ciphertext, ciphertext_len);


  printf("\nCiphertext is: ");
  print_hex(ciphertext,ciphertext_len);

  /* Decrypt the ciphertext */
  // decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,decryptedtext);

  /* Add a NULL to decryptedtext */
  // decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  //  printf("\n Decrypted text is: %s", decryptedtext);

 /* Check if decrypted text matches the original plaintext */
 

char* finalCipher = (char*) malloc (2 * ciphertext_len + 1);
char* finalCipher_ = finalCipher;
 for(int i=0; i< ciphertext_len; i++){
   finalCipher_  += sprintf(finalCipher_, "%02x", ciphertext[i]);
 }
 *(finalCipher_ + 1) = '\0';


  if(strcmp((const char*)ciphertextGiven, (const char*)finalCipher) == 0){
     *(key + 16) = '\0';
      printf("\nThe key from the WordList.txt file :- %s\n", key);
      printf("\n:-) Hurray! %s is a match! \n", plaintext);
      abort();
      fclose(fp);
  }else {
      printf("\nOriginal Cipertext for \"%s\" is %s, \nand Generated cipertext is ", plaintext, ciphertextGiven);    
      print_hex( ciphertext,ciphertext_len);
      printf("\n:-( Sorry, decrypted text does not match the original plaintext!\n");
  }
    }
    fclose(fp);
}

  return 0;
}



