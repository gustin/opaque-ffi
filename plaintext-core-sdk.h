#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  const uint8_t *beta;
  const uint8_t *v;
  const uint8_t *envelope;
  const uint8_t *ke_2;
  const uint8_t *y;
} Authentication;

typedef struct {
  const uint8_t *alpha;
  const uint8_t *pub_u;
  const uint8_t *priv_u;
} ClientRegistration;

typedef struct {
  const uint8_t *beta;
  const uint8_t *v;
  const uint8_t *pub_s;
} Registration;

char *authenticate_finalize(const char *username, const uint8_t *key, const uint8_t *x);

Authentication authenticate_start(const char *username, const uint8_t *alpha, const uint8_t *key);

bool confirm_second_factor(const char *user_id, const char *code);

void free_qr_code(char *qr);

void free_token(char *token);

char *generate_qr_code(const char *user_id);

const uint8_t *opaque_client_registration_finalize(const char *password,
                                                   const uint8_t *beta,
                                                   const uint8_t *v,
                                                   const uint8_t *pub_u,
                                                   const uint8_t *pub_s,
                                                   const uint8_t *priv_u);

ClientRegistration opaque_client_registration_start(const char *password);

void registration_finalize(const char *username, const uint8_t *pub_u, const uint8_t *envelope);

Registration registration_start(const char *username, const uint8_t *alpha);

void webauthn_free_challenge(char *challenge);

bool webauthn_register_credential(char *username, char *credential);

char *webauthn_registration_challenge(char *username);
