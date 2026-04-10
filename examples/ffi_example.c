/**
 * Example C program demonstrating the NWabiSabi FFI
 *
 * Compile with:
 *   gcc -o ffi_example examples/ffi_example.c -L target/release -lnwabisabi -lpthread -ldl -lm
 *
 * Run with:
 *   LD_LIBRARY_PATH=target/release ./ffi_example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nwabisabi.h"

void print_error(const char* operation, FFIError error) {
    fprintf(stderr, "[ERROR] %s failed with code: %d\n", operation, error);
}

int main() {
    FFIError error = Success;

    printf("NWabiSabi FFI Example\n");
    printf("Version: %s\n\n", wabisabi_version());

    // 1. Create random number generator
    printf("Creating random number generator...\n");
    OpaqueRandom* random = wabisabi_random_create(&error);
    if (random == NULL) {
        print_error("wabisabi_random_create", error);
        return 1;
    }
    printf("✓ Random created\n\n");

    // 2. Create credential issuer (coordinator)
    printf("Creating credential issuer...\n");
    FFIGroupElement cw, i;
    long long initial_balance = 1000000;

    OpaqueIssuer* issuer = wabisabi_issuer_create_random(
        random,
        initial_balance,
        &cw,
        &i,
        &error
    );

    if (issuer == NULL) {
        print_error("wabisabi_issuer_create_random", error);
        wabisabi_random_destroy(random);
        return 1;
    }

    long long balance = wabisabi_issuer_get_balance(issuer);
    printf("✓ Issuer created with balance: %lld\n", balance);
    printf("  Cw (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...\n",
           cw.compressed[0], cw.compressed[1], cw.compressed[2], cw.compressed[3],
           cw.compressed[4], cw.compressed[5], cw.compressed[6], cw.compressed[7]);
    printf("  I  (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...\n\n",
           i.compressed[0], i.compressed[1], i.compressed[2], i.compressed[3],
           i.compressed[4], i.compressed[5], i.compressed[6], i.compressed[7]);

    // 3. Create WabiSabi client
    printf("Creating WabiSabi client...\n");
    OpaqueClient* client = wabisabi_client_create(&cw, &i, &error);
    if (client == NULL) {
        print_error("wabisabi_client_create", error);
        wabisabi_issuer_destroy(issuer);
        wabisabi_random_destroy(random);
        return 1;
    }
    printf("✓ Client created\n\n");

    // 4. Client creates zero-value credential request
    printf("Creating zero-value credential request...\n");
    FFIScalarArray randomness;
    void* zero_request = wabisabi_client_create_zero_request(
        client,
        random,
        &randomness,
        &error
    );

    if (zero_request == NULL) {
        print_error("wabisabi_client_create_zero_request", error);
        wabisabi_client_destroy(client);
        wabisabi_issuer_destroy(issuer);
        wabisabi_random_destroy(random);
        return 1;
    }
    printf("✓ Zero request created\n");
    printf("  Randomness count: %zu\n\n", randomness.length);

    // 5. Clean up
    printf("Cleaning up...\n");
    wabisabi_free_scalar_array(randomness);
    // Note: zero_request cleanup would require additional FFI functions
    wabisabi_client_destroy(client);
    wabisabi_issuer_destroy(issuer);
    wabisabi_random_destroy(random);
    printf("✓ All resources freed\n\n");

    printf("Example completed successfully!\n");
    return 0;
}
