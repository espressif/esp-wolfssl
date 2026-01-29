/*
 * ESP-IDF FreeRTOS memory allocation wrappers for wolfSSL
 * Provides wc_pvPortMalloc and wc_pvPortFree used by newer wolfSSL versions
 */
#include <stdlib.h>
#include <stddef.h>

/* wolfSSL expects these functions when WOLFSSL_ESPIDF is defined */
void* wc_pvPortMalloc(size_t xWantedSize)
{
    return malloc(xWantedSize);
}

void wc_pvPortFree(void* pv)
{
    free(pv);
}

void* wc_pvPortRealloc(void* pv, size_t xWantedSize)
{
    return realloc(pv, xWantedSize);
}
