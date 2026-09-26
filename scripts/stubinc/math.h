#pragma once
double sin(double); double cos(double); double tan(double); double sqrt(double); double exp(double); double log(double);
double pow(double, double); double fabs(double); double floor(double); double ceil(double); double atan2(double, double);
double atan(double); double fmod(double, double); double log2(double); double log10(double); double tanh(double); double hypot(double,double);
double round(double); double asin(double); double acos(double); double sinh(double); double cosh(double); double trunc(double);
float sinf(float); float cosf(float); float sqrtf(float); float expf(float); float logf(float); float fabsf(float); float powf(float,float);
float floorf(float); float atan2f(float,float); float tanhf(float); float roundf(float); float fmodf(float,float); float ceilf(float); float tanf(float);
#define M_PI 3.14159265358979323846
#define M_E 2.7182818284590452354
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define HUGE_VAL (__builtin_huge_val())
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)
