#include "Limelight-internal.h"
#include "PlatformCrypto.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

STREAM_CONFIGURATION StreamConfig;
CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;

#include "../src/RtspConnection.c"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "CHECK failed: %s at %s:%d\n", #x, __FILE__, __LINE__); exit(2); } } while (0)

static void log_message(const char* fmt, ...) { (void)fmt; }
static void make_iv(uint8_t iv[12], uint32_t seq, char origin) {
    memset(iv, 0, 12);
    iv[0] = (uint8_t)seq; iv[1] = (uint8_t)(seq >> 8);
    iv[2] = (uint8_t)(seq >> 16); iv[3] = (uint8_t)(seq >> 24);
    iv[10] = (uint8_t)origin; iv[11] = 'R';
}
static char* encrypt_response(uint32_t seq, const char* cseq, int* out_len) {
    char plain[512];
    int plain_len = snprintf(plain, sizeof(plain), "RTSP/1.0 200 OK\r\n%s%s\r\n", cseq ? "CSeq: " : "", cseq ? cseq : "");
    ENC_RTSP_HEADER* enc = calloc(1, sizeof(*enc) + (size_t)plain_len);
    CHECK(enc != NULL);
    enc->typeAndLength = BE32(ENCRYPTED_RTSP_BIT | (uint32_t)plain_len);
    enc->sequenceNumber = BE32(seq);
    uint8_t iv[12]; make_iv(iv, seq, 'H');
    int cipher_len = 0;
    CHECK(PltEncryptMessage(encryptionCtx, ALGORITHM_AES_GCM, 0,
          (uint8_t*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
          iv, sizeof(iv), enc->tag, sizeof(enc->tag), (uint8_t*)plain, plain_len,
          (uint8_t*)(enc + 1), &cipher_len));
    CHECK(cipher_len == plain_len);
    *out_len = (int)sizeof(*enc) + cipher_len;
    return (char*)enc;
}
static bool transaction(const char* command, uint32_t response_seq, const char* cseq,
                       int expected_ok, int expected_request_seq) {
    RTSP_MESSAGE request = {0}, server_request = {0}, response = {0};
    currentSeqNumber = expected_request_seq;
    CHECK(initializeRtspRequest(&request, (char*)command, (char*)"rtsp://127.0.0.1/session"));
    int request_len = 0;
    char* wire_request = sealRtspMessage(&request, &request_len);
    CHECK(wire_request != NULL && request_len > (int)sizeof(ENC_RTSP_HEADER));
    // Server-side authenticated decrypt and actual common-c parser of the full request.
    ENC_RTSP_HEADER* enc_request = (ENC_RTSP_HEADER*)wire_request;
    uint32_t req_seq = BE32(enc_request->sequenceNumber);
    uint8_t req_iv[12]; make_iv(req_iv, req_seq, 'C');
    int req_plain_len = request_len - (int)sizeof(*enc_request);
    char* req_plain = malloc((size_t)req_plain_len + 1); CHECK(req_plain != NULL);
    CHECK(PltDecryptMessage(decryptionCtx, ALGORITHM_AES_GCM, 0,
          (uint8_t*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
          req_iv, sizeof(req_iv), enc_request->tag, sizeof(enc_request->tag),
          (uint8_t*)(enc_request + 1), req_plain_len, (uint8_t*)req_plain, &req_plain_len));
    CHECK(parseRtspMessage(&server_request, req_plain, req_plain_len) == RTSP_ERROR_SUCCESS);
    CHECK(server_request.type == TYPE_REQUEST);
    CHECK(server_request.sequenceNumber == expected_request_seq);
    CHECK(strcmp(server_request.message.request.command, command) == 0);
    free(req_plain); free(wire_request);

    int response_len = 0;
    char* raw_response = encrypt_response(response_seq, cseq, &response_len);
    bool accepted = unsealRtspMessage(raw_response, response_len, &request, &response);
    free(raw_response);
    CHECK(accepted == (expected_ok != 0));
    if (accepted) freeMessage(&response);
    freeMessage(&server_request); freeMessage(&request);
    return accepted;
}
int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--check-fail") == 0) CHECK(false);
    ListenerCallbacks.logMessage = log_message;
    memset(StreamConfig.remoteInputAesKey, 0x5a, sizeof(StreamConfig.remoteInputAesKey));
    encryptionCtx = PltCreateCryptoContext(); decryptionCtx = PltCreateCryptoContext();
    CHECK(encryptionCtx != NULL && decryptionCtx != NULL);
    encryptedRtspEnabled = true; useEnet = false; rtspClientVersion = 1;
    strcpy(urlAddr, "127.0.0.1");
    encryptionSequenceNumber = 0; lastDecryptionSequenceNumber = 0;

    CHECK(transaction("OPTIONS", 1, "1", 1, 1));
    printf("tx=OPTIONS request_cseq=1 response_iv=1 accepted=1\n");
    CHECK(transaction("DESCRIBE", 2, NULL, 1, 2));
    printf("tx=DESCRIBE request_cseq=2 response_cseq=absent response_iv=2 accepted=1\n");
    const char* malformed_cseqs[] = {"", "nonnumeric", "12junk", "2147483648", "+3"};
    for (unsigned i = 0; i < sizeof(malformed_cseqs) / sizeof(malformed_cseqs[0]); i++) {
        CHECK(!transaction("SETUP", 3, malformed_cseqs[i], 0, 3));
    }
    printf("tx=SETUP request_cseq=3 response_cseq=empty,nonnumeric,trailing-junk,overflow,plus-prefixed response_iv=3 accepted=0; last_iv_uncommitted=1\n");
    CHECK(transaction("SETUP", 3, "0004", 1, 4));
    printf("tx=SETUP request_cseq=4 response_cseq=0004 response_iv=3 accepted=1\n");
    CHECK(!transaction("PLAY", 4, "999", 0, 5));
    printf("tx=PLAY request_cseq=5 response_cseq=mismatch response_iv=4 accepted=0\n");
    CHECK(transaction("PLAY", 4, "5", 1, 5));
    printf("tx=PLAY request_cseq=5 response_cseq=5 response_iv=4 accepted=1; mismatch_iv_uncommitted=1\n");
    CHECK(!transaction("PLAY", 4, "5", 0, 5));
    printf("tx=PLAY request_cseq=5 response_iv=replay(4) accepted=0\n");
    CHECK(!transaction("PLAY", 3, "5", 0, 5));
    printf("tx=PLAY request_cseq=5 response_iv=decreasing(3) accepted=0\n");
    memset(StreamConfig.remoteInputAesKey, 0x6b, sizeof(StreamConfig.remoteInputAesKey));
    encryptionSequenceNumber = 0; // New session key permits fresh sequence space.
    lastDecryptionSequenceNumber = 0;
    CHECK(transaction("OPTIONS", 1, "1", 1, 1));
    printf("reconnect=new-key tx=OPTIONS request_cseq=1 response_iv=1 accepted=1\n");
    PltDestroyCryptoContext(encryptionCtx); PltDestroyCryptoContext(decryptionCtx);
    return 0;
}
