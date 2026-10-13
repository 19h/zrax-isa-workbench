/* Synthetic program for the zrax Mach-O fixtures (see README.md). */
#include <stddef.h>

unsigned checksum(const unsigned char *data, size_t size)
{
    unsigned sum = 0;
    for (size_t i = 0; i < size; i++)
        sum = (sum << 5) + sum + data[i];
    return sum;
}

void scale(float *out, const float *in, float factor, size_t count)
{
    for (size_t i = 0; i < count; i++)
        out[i] = in[i] * factor + out[i];
}

int dot(const int *a, const int *b, size_t count)
{
    int total = 0;
    for (size_t i = 0; i < count; i++)
        total += a[i] * b[i];
    return total;
}

int main(int argc, char **argv)
{
    float values[64] = {0};
    int numbers[64] = {0};
    scale(values, values, (float)argc, 64);
    return (int)checksum((const unsigned char *)argv[0], (size_t)argc)
        + dot(numbers, numbers, 64) + (int)values[3];
}
